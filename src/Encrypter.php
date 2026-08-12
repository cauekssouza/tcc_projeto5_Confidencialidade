<?php

namespace Illuminate\Encryption;

use Illuminate\Contracts\Encryption\DecryptException;
use Illuminate\Contracts\Encryption\Encrypter as EncrypterContract;
use Illuminate\Contracts\Encryption\EncryptException;
use Illuminate\Contracts\Encryption\StringEncrypter;
use JsonException;
use RuntimeException;

class Encrypter implements EncrypterContract, StringEncrypter
{
    /**
     * The encryption key.
     *
     * @var string
     */
    protected $key;

    /**
     * The previous / legacy encryption keys.
     *
     * @var array
     */
    protected $previousKeys = [];

    /**
     * The normalized cipher used for encryption.
     *
     * @var string
     */
    protected $cipher;

    /**
     * Cipher metadata cached for the current instance.
     *
     * @var array{size: int, aead: bool}
     */
    private $cipherConfig;

    /**
     * Supported cipher algorithms and their properties.
     *
     * @var array<string, array{size: int, aead: bool}>
     */
    private static $supportedCiphers = [
        'aes-128-cbc' => ['size' => 16, 'aead' => false],
        'aes-256-cbc' => ['size' => 32, 'aead' => false],
        'aes-128-gcm' => ['size' => 16, 'aead' => true],
        'aes-256-gcm' => ['size' => 32, 'aead' => true],
    ];

    /**
     * Create a new encrypter instance.
     *
     * @param  string  $key
     * @param  string  $cipher
     *
     * @throws \RuntimeException
     */
    public function __construct(
        #[\SensitiveParameter] $key,
        $cipher = 'aes-128-cbc'
    ) {
        $key = (string) $key;
        $cipher = strtolower((string) $cipher);

        if (! static::supported($key, $cipher)) {
            throw new RuntimeException(
                'Unsupported cipher or incorrect key length.'
            );
        }

        $this->key = $key;
        $this->cipher = $cipher;
        $this->cipherConfig = self::$supportedCiphers[$cipher];
    }

    /**
     * Determine if the given key and cipher combination is valid.
     *
     * @param  string  $key
     * @param  string  $cipher
     * @return bool
     */
    public static function supported(
        #[\SensitiveParameter] $key,
        $cipher
    ) {
        $cipher = strtolower((string) $cipher);
        $config = self::$supportedCiphers[$cipher] ?? null;

        return $config !== null
            && strlen((string) $key) === $config['size'];
    }

    /**
     * Create a new encryption key for the given cipher.
     *
     * @param  string  $cipher
     * @return string
     *
     * @throws \RuntimeException
     */
    public static function generateKey($cipher)
    {
        $cipher = strtolower((string) $cipher);
        $config = self::$supportedCiphers[$cipher] ?? null;

        if ($config === null) {
            throw new RuntimeException('Unsupported cipher.');
        }

        return random_bytes($config['size']);
    }

    /**
     * Encrypt the given value.
     *
     * @param  mixed  $value
     * @param  bool  $serialize
     * @return string
     *
     * @throws \Illuminate\Contracts\Encryption\EncryptException
     */
    public function encrypt(
        #[\SensitiveParameter] $value,
        $serialize = true
    ) {
        try {
            $ivLength = openssl_cipher_iv_length($this->cipher);

            if ($ivLength === false || $ivLength <= 0) {
                throw new EncryptException('Could not encrypt the data.');
            }

            $iv = random_bytes($ivLength);

            $plaintext = $serialize
                ? serialize($value)
                : $value;

            $tag = '';

            $encrypted = \openssl_encrypt(
                $plaintext,
                $this->cipher,
                $this->key,
                0,
                $iv,
                $tag
            );

            if ($encrypted === false) {
                throw new EncryptException('Could not encrypt the data.');
            }

            $encodedIv = base64_encode($iv);
            $encodedTag = $this->cipherConfig['aead']
                ? base64_encode($tag)
                : '';

            $mac = $this->cipherConfig['aead']
                ? ''
                : $this->hash($encodedIv, $encrypted, $this->key);

            $json = json_encode(
                [
                    'iv' => $encodedIv,
                    'value' => $encrypted,
                    'mac' => $mac,
                    'tag' => $encodedTag,
                ],
                JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR
            );

            return base64_encode($json);
        } catch (EncryptException $e) {
            throw $e;
        } catch (\Throwable $e) {
            /*
             * Do not propagate OpenSSL, JSON, serialization or infrastructure
             * details to the caller.
             */
            throw new EncryptException('Could not encrypt the data.');
        }
    }

    /**
     * Encrypt a string without serialization.
     *
     * @param  string  $value
     * @return string
     */
    public function encryptString(
        #[\SensitiveParameter] $value
    ) {
        return $this->encrypt($value, false);
    }

    /**
     * Decrypt the given value.
     *
     * @param  string  $payload
     * @param  bool  $unserialize
     * @return mixed
     *
     * @throws \Illuminate\Contracts\Encryption\DecryptException
     */
    public function decrypt(
        #[\SensitiveParameter] $payload,
        $unserialize = true
    ) {
        try {
            $payload = $this->getJsonPayload($payload);

            $iv = base64_decode($payload['iv'], true);

            if ($iv === false) {
                throw new DecryptException('The payload is invalid.');
            }

            $tag = $this->decodeTag($payload);

            if ($this->shouldValidateMac()) {
                $decrypted = $this->decryptWithMac(
                    $payload,
                    $iv,
                    $tag
                );
            } else {
                $decrypted = $this->decryptWithAvailableKeys(
                    $payload,
                    $iv,
                    $tag
                );
            }

            if ($decrypted === false) {
                throw new DecryptException('Could not decrypt the data.');
            }

            return $unserialize
                ? unserialize($decrypted)
                : $decrypted;
        } catch (DecryptException $e) {
            throw $e;
        } catch (\Throwable $e) {
            /*
             * Prevent details about OpenSSL, serialization, key rotation or
             * malformed internal structures from escaping to the caller.
             */
            throw new DecryptException('Could not decrypt the data.');
        }
    }

    /**
     * Decrypt CBC payload after authenticating the ciphertext.
     *
     * Authentication is performed before decryption so unauthenticated
     * ciphertext never reaches openssl_decrypt().
     *
     * @param  array  $payload
     * @param  string  $iv
     * @param  string|null  $tag
     * @return string|false
     */
    private function decryptWithMac(
        array $payload,
        $iv,
        $tag
    ) {
        $validKey = null;

        /*
         * Intentionally validate every configured key rather than returning
         * immediately after the first match. This reduces key-position
         * dependent timing differences during key rotation.
         */
        foreach ($this->getAllKeys() as $key) {
            $valid = $this->validMacForKey($payload, $key);

            if ($valid && $validKey === null) {
                $validKey = $key;
            }
        }

        if ($validKey === null) {
            throw new DecryptException('The MAC is invalid.');
        }

        return \openssl_decrypt(
            $payload['value'],
            $this->cipher,
            $validKey,
            0,
            $iv,
            $tag ?? ''
        );
    }

    /**
     * Attempt authenticated AEAD decryption with all configured keys.
     *
     * @param  array  $payload
     * @param  string  $iv
     * @param  string|null  $tag
     * @return string|false
     */
    private function decryptWithAvailableKeys(
        array $payload,
        $iv,
        $tag
    ) {
        foreach ($this->getAllKeys() as $key) {
            $decrypted = \openssl_decrypt(
                $payload['value'],
                $this->cipher,
                $key,
                0,
                $iv,
                $tag ?? ''
            );

            if ($decrypted !== false) {
                return $decrypted;
            }
        }

        return false;
    }

    /**
     * Decode and validate the authentication tag.
     *
     * @param  array  $payload
     * @return string|null
     */
    private function decodeTag(array $payload)
    {
        if (empty($payload['tag'])) {
            $tag = null;
        } else {
            $tag = base64_decode($payload['tag'], true);

            if ($tag === false) {
                throw new DecryptException('Could not decrypt the data.');
            }
        }

        $this->ensureTagIsValid($tag);

        return $tag;
    }

    /**
     * Decrypt the given string without unserialization.
     *
     * @param  string  $payload
     * @return string
     */
    public function decryptString(
        #[\SensitiveParameter] $payload
    ) {
        return $this->decrypt($payload, false);
    }

    /**
     * Create a MAC for the given value.
     *
     * @param  string  $iv
     * @param  mixed  $value
     * @param  string  $key
     * @return string
     */
    protected function hash(
        #[\SensitiveParameter] $iv,
        #[\SensitiveParameter] $value,
        #[\SensitiveParameter] $key
    ) {
        return hash_hmac(
            'sha256',
            $iv.$value,
            $key
        );
    }

    /**
     * Get the JSON array from the given payload.
     *
     * @param  string  $payload
     * @return array
     *
     * @throws \Illuminate\Contracts\Encryption\DecryptException
     */
    protected function getJsonPayload(
        #[\SensitiveParameter] $payload
    ) {
        if (! is_string($payload)) {
            throw new DecryptException('The payload is invalid.');
        }

        $decoded = base64_decode($payload, true);

        if ($decoded === false) {
            throw new DecryptException('The payload is invalid.');
        }

        try {
            $decodedPayload = json_decode(
                $decoded,
                true,
                512,
                JSON_THROW_ON_ERROR
            );
        } catch (JsonException $e) {
            throw new DecryptException('The payload is invalid.');
        }

        if (! $this->validPayload($decodedPayload)) {
            throw new DecryptException('The payload is invalid.');
        }

        return $decodedPayload;
    }

    /**
     * Verify that the encryption payload is valid.
     *
     * @param  mixed  $payload
     * @return bool
     */
    protected function validPayload($payload)
    {
        if (! is_array($payload)) {
            return false;
        }

        foreach (['iv', 'value', 'mac'] as $item) {
            if (
                ! array_key_exists($item, $payload)
                || ! is_string($payload[$item])
            ) {
                return false;
            }
        }

        if (
            array_key_exists('tag', $payload)
            && ! is_string($payload['tag'])
        ) {
            return false;
        }

        $iv = base64_decode($payload['iv'], true);

        if ($iv === false) {
            return false;
        }

        $expectedIvLength = openssl_cipher_iv_length(
            $this->cipher
        );

        return $expectedIvLength !== false
            && strlen($iv) === $expectedIvLength;
    }

    /**
     * Determine if the MAC for the given payload is valid
     * for the primary key.
     *
     * @param  array  $payload
     * @return bool
     */
    protected function validMac(array $payload)
    {
        return $this->validMacForKey(
            $payload,
            $this->key
        );
    }

    /**
     * Determine if the MAC is valid for the given payload and key.
     *
     * Uses constant-time comparison to prevent timing attacks.
     *
     * @param  array  $payload
     * @param  string  $key
     * @return bool
     */
    protected function validMacForKey(
        #[\SensitiveParameter] $payload,
        #[\SensitiveParameter] $key
    ) {
        $calculatedMac = $this->hash(
            $payload['iv'],
            $payload['value'],
            $key
        );

        return hash_equals(
            $calculatedMac,
            $payload['mac']
        );
    }

    /**
     * Ensure the given tag is valid for the selected cipher.
     *
     * @param  string|null  $tag
     * @return void
     *
     * @throws \Illuminate\Contracts\Encryption\DecryptException
     */
    protected function ensureTagIsValid($tag)
    {
        if ($this->cipherConfig['aead']) {
            if (! is_string($tag) || strlen($tag) !== 16) {
                throw new DecryptException(
                    'Could not decrypt the data.'
                );
            }

            return;
        }

        if ($tag !== null) {
            throw new DecryptException(
                'Could not decrypt the data.'
            );
        }
    }

    /**
     * Determine if we should validate a separate MAC.
     *
     * @return bool
     */
    protected function shouldValidateMac()
    {
        return ! $this->cipherConfig['aead'];
    }

    /**
     * Determine if the given value appears to be encrypted.
     *
     * This method only validates the envelope structure.
     * It does not authenticate or decrypt the payload.
     *
     * @param  mixed  $value
     * @return bool
     */
    public static function appearsEncrypted($value)
    {
        if (! is_string($value)) {
            return false;
        }

        $decoded = base64_decode($value, true);

        if ($decoded === false) {
            return false;
        }

        try {
            $payload = json_decode(
                $decoded,
                true,
                512,
                JSON_THROW_ON_ERROR
            );
        } catch (JsonException $e) {
            return false;
        }

        return is_array($payload)
            && isset(
                $payload['iv'],
                $payload['value'],
                $payload['mac']
            )
            && is_string($payload['iv'])
            && is_string($payload['value'])
            && is_string($payload['mac']);
    }

    /**
     * Get the current encryption key.
     *
     * @return string
     */
    public function getKey()
    {
        return $this->key;
    }

    /**
     * Get the current and previous encryption keys.
     *
     * @return array
     */
    public function getAllKeys()
    {
        return [
            $this->key,
            ...$this->previousKeys,
        ];
    }

    /**
     * Get the previous encryption keys.
     *
     * @return array
     */
    public function getPreviousKeys()
    {
        return $this->previousKeys;
    }

    /**
     * Set previous / legacy encryption keys.
     *
     * @param  array  $keys
     * @return $this
     *
     * @throws \RuntimeException
     */
    public function previousKeys(
        #[\SensitiveParameter] array $keys
    ) {
        foreach ($keys as $key) {
            if (! static::supported($key, $this->cipher)) {
                /*
                 * Avoid exposing configuration details unnecessarily
                 * through an exception returned to higher layers.
                 */
                throw new RuntimeException(
                    'Invalid encryption key configuration.'
                );
            }
        }

        $this->previousKeys = array_values($keys);

        return $this;
    }
}
