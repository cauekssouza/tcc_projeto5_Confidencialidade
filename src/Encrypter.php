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
     * The algorithm used for encryption.
     *
     * @var string
     */
    protected $cipher;

    /**
     * The supported cipher algorithms and their properties.
     *
     * @var array
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

        if (! isset(self::$supportedCiphers[$cipher])) {
            throw new RuntimeException('Unsupported cipher.');
        }

        return random_bytes(self::$supportedCiphers[$cipher]['size']);
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
        $ivLength = openssl_cipher_iv_length($this->cipher);

        if ($ivLength === false || $ivLength <= 0) {
            throw new EncryptException('Could not encrypt the data.');
        }

        $iv = random_bytes($ivLength);
        $tag = null;

        $plaintext = $serialize
            ? serialize($value)
            : $value;

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
        $encodedTag = base64_encode($tag ?? '');

        $mac = $this->shouldValidateMac()
            ? $this->hash($encodedIv, $encrypted, $this->key)
            : '';

        try {
            $json = json_encode(
                [
                    'iv' => $encodedIv,
                    'value' => $encrypted,
                    'mac' => $mac,
                    'tag' => $encodedTag,
                ],
                JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR
            );
        } catch (JsonException $e) {
            throw new EncryptException('Could not encrypt the data.');
        }

        return base64_encode($json);
    }

    /**
     * Encrypt a string without serialization.
     *
     * @param  string  $value
     * @return string
     *
     * @throws \Illuminate\Contracts\Encryption\EncryptException
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
    public function decrypt($payload, $unserialize = true)
    {
        $payload = $this->getJsonPayload($payload);

        $iv = base64_decode($payload['iv'], true);

        if ($iv === false) {
            throw new DecryptException('Could not decrypt the data.');
        }

        $tag = $this->decodeAndValidateTag($payload);

        $keys = $this->getAllKeys();
        $validateMac = $this->shouldValidateMac();

        $decrypted = false;

        if ($validateMac) {
            /*
             * Evaluate every configured key rather than stopping at the first
             * MAC match. Besides allowing key rotation, this avoids exposing
             * the key position through a trivial early-exit timing difference.
             */
            $validKey = null;

            foreach ($keys as $key) {
                $validMac = $this->validMacForKey($payload, $key);

                if ($validMac && $validKey === null) {
                    $validKey = $key;
                }
            }

            if ($validKey !== null) {
                $decrypted = \openssl_decrypt(
                    $payload['value'],
                    $this->cipher,
                    $validKey,
                    0,
                    $iv
                );
            }
        } else {
            /*
             * AEAD authentication is performed by OpenSSL using the GCM tag.
             *
             * All keys are attempted even after a successful decryption so
             * previous-key ordering is not directly exposed by an early exit.
             */
            foreach ($keys as $key) {
                $candidate = \openssl_decrypt(
                    $payload['value'],
                    $this->cipher,
                    $key,
                    0,
                    $iv,
                    $tag
                );

                if ($candidate !== false && $decrypted === false) {
                    $decrypted = $candidate;
                }
            }
        }

        /*
         * Do not distinguish MAC failures, authentication failures,
         * incorrect keys or malformed ciphertext to the caller.
         */
        if ($decrypted === false) {
            throw new DecryptException('Could not decrypt the data.');
        }

        return $unserialize
            ? unserialize($decrypted)
            : $decrypted;
    }

    /**
     * Decrypt the given string without unserialization.
     *
     * @param  string  $payload
     * @return string
     *
     * @throws \Illuminate\Contracts\Encryption\DecryptException
     */
    public function decryptString($payload)
    {
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
    protected function getJsonPayload($payload)
    {
        if (! is_string($payload)) {
            throw new DecryptException('Could not decrypt the data.');
        }

        $decoded = base64_decode($payload, true);

        if ($decoded === false) {
            throw new DecryptException('Could not decrypt the data.');
        }

        try {
            $payload = json_decode(
                $decoded,
                true,
                512,
                JSON_THROW_ON_ERROR
            );
        } catch (JsonException $e) {
            throw new DecryptException('Could not decrypt the data.');
        }

        if (! $this->validPayload($payload)) {
            throw new DecryptException('Could not decrypt the data.');
        }

        return $payload;
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

        $expectedIvLength = openssl_cipher_iv_length($this->cipher);

        return $expectedIvLength !== false
            && strlen($iv) === $expectedIvLength;
    }

    /**
     * Determine if the MAC for the given payload is valid for the primary key.
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
     * @param  array  $payload
     * @param  string  $key
     * @return bool
     */
    protected function validMacForKey(
        #[\SensitiveParameter] $payload,
        #[\SensitiveParameter] $key
    ) {
        $expectedMac = $this->hash(
            $payload['iv'],
            $payload['value'],
            $key
        );

        /*
         * The calculated value (secret/known string) must be the first
         * argument and the untrusted payload MAC the second.
         */
        return hash_equals(
            $expectedMac,
            $payload['mac']
        );
    }

    /**
     * Ensure the given tag is a valid tag given the selected cipher.
     *
     * @param  string|null  $tag
     * @return void
     *
     * @throws \Illuminate\Contracts\Encryption\DecryptException
     */
    protected function ensureTagIsValid($tag)
    {
        if ($this->isAead()) {
            if (! is_string($tag) || strlen($tag) !== 16) {
                throw new DecryptException(
                    'Could not decrypt the data.'
                );
            }

            return;
        }

        /*
         * CBC payloads must not carry an authentication tag.
         * Authentication is provided by HMAC instead.
         */
        if ($tag !== null) {
            throw new DecryptException(
                'Could not decrypt the data.'
            );
        }
    }

    /**
     * Decode and validate the authentication tag.
     *
     * @param  array  $payload
     * @return string|null
     *
     * @throws \Illuminate\Contracts\Encryption\DecryptException
     */
    private function decodeAndValidateTag(array $payload)
    {
        $encodedTag = $payload['tag'] ?? '';

        if (! $this->isAead()) {
            /*
             * Encryption performed by this class writes an empty tag for CBC.
             * Reject any non-empty tag, including malformed Base64 values.
             */
            if ($encodedTag !== '') {
                throw new DecryptException(
                    'Could not decrypt the data.'
                );
            }

            $this->ensureTagIsValid(null);

            return null;
        }

        if ($encodedTag === '') {
            throw new DecryptException(
                'Could not decrypt the data.'
            );
        }

        $tag = base64_decode($encodedTag, true);

        if ($tag === false) {
            throw new DecryptException(
                'Could not decrypt the data.'
            );
        }

        $this->ensureTagIsValid($tag);

        return $tag;
    }

    /**
     * Determine if we should validate the MAC while decrypting.
     *
     * @return bool
     */
    protected function shouldValidateMac()
    {
        return ! $this->isAead();
    }

    /**
     * Determine whether the configured cipher is AEAD.
     *
     * @return bool
     */
    private function isAead()
    {
        return self::$supportedCiphers[$this->cipher]['aead'];
    }

    /**
     * Determine if the given value appears to be encrypted by this encrypter.
     *
     * This method performs only structural detection. It does not establish
     * authenticity or prove that the payload can be decrypted.
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
            && is_string($payload['mac'])
            && (
                ! isset($payload['tag'])
                || is_string($payload['tag'])
            );
    }

    /**
     * Get the encryption key that the encrypter is currently using.
     *
     * @return string
     */
    public function getKey()
    {
        return $this->key;
    }

    /**
     * Get the current encryption key and all previous encryption keys.
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
     * Set the previous / legacy encryption keys that should be utilized
     * if decryption fails.
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
                throw new RuntimeException(
                    'Unsupported cipher or incorrect key length.'
                );
            }
        }

        $this->previousKeys = $keys;

        return $this;
    }
}
