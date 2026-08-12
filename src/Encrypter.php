<?php

namespace Illuminate\Encryption;

use Illuminate\Contracts\Encryption\DecryptException;
use Illuminate\Contracts\Encryption\Encrypter as EncrypterContract;
use Illuminate\Contracts\Encryption\EncryptException;
use Illuminate\Contracts\Encryption\StringEncrypter;
use JsonException;
use RuntimeException;
use Throwable;

class Encrypter implements EncrypterContract, StringEncrypter
{
    /**
     * Generic errors deliberately avoid exposing cryptographic details.
     */
    private const ENCRYPTION_ERROR = 'Could not encrypt the data.';
    private const DECRYPTION_ERROR = 'Could not decrypt the data.';
    private const CONFIGURATION_ERROR = 'Invalid encryption configuration.';

    /**
     * Supported cipher algorithms and their properties.
     *
     * @var array<string, array{size: int, aead: bool}>
     */
    private const SUPPORTED_CIPHERS = [
        'aes-128-cbc' => ['size' => 16, 'aead' => false],
        'aes-256-cbc' => ['size' => 32, 'aead' => false],
        'aes-128-gcm' => ['size' => 16, 'aead' => true],
        'aes-256-gcm' => ['size' => 32, 'aead' => true],
    ];

    /**
     * Authentication tag size used by AES-GCM.
     */
    private const GCM_TAG_LENGTH = 16;

    /**
     * The encryption key.
     *
     * @var string
     */
    protected $key;

    /**
     * Previous / legacy encryption keys.
     *
     * @var array<int, string>
     */
    protected $previousKeys = [];

    /**
     * Normalized cipher name.
     *
     * @var string
     */
    protected $cipher;

    /**
     * Whether the selected cipher provides AEAD.
     *
     * Cached to avoid repeated lookups.
     *
     * @var bool
     */
    private $aead;

    /**
     * Cipher IV length.
     *
     * Cached because it is constant for the lifetime of this instance.
     *
     * @var int
     */
    private $ivLength;

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
        $cipher = self::normalizeCipher($cipher);

        if (! static::supported($key, $cipher)) {
            throw new RuntimeException(self::CONFIGURATION_ERROR);
        }

        $ivLength = openssl_cipher_iv_length($cipher);

        if ($ivLength === false || $ivLength <= 0) {
            throw new RuntimeException(self::CONFIGURATION_ERROR);
        }

        $this->key = $key;
        $this->cipher = $cipher;
        $this->aead = self::SUPPORTED_CIPHERS[$cipher]['aead'];
        $this->ivLength = $ivLength;
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
        $cipher = self::normalizeCipher($cipher);
        $configuration = self::SUPPORTED_CIPHERS[$cipher] ?? null;

        return $configuration !== null
            && strlen((string) $key) === $configuration['size'];
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
        $cipher = self::normalizeCipher($cipher);
        $configuration = self::SUPPORTED_CIPHERS[$cipher] ?? null;

        if ($configuration === null) {
            throw new RuntimeException(self::CONFIGURATION_ERROR);
        }

        return random_bytes($configuration['size']);
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
            $iv = random_bytes($this->ivLength);

            $plaintext = $serialize
                ? serialize($value)
                : (string) $value;

            $tag = '';

            $encrypted = \openssl_encrypt(
                $plaintext,
                $this->cipher,
                $this->key,
                0,
                $iv,
                $tag,
                '',
                self::GCM_TAG_LENGTH
            );

            if ($encrypted === false) {
                throw new EncryptException(self::ENCRYPTION_ERROR);
            }

            $encodedIv = base64_encode($iv);
            $encodedTag = $this->aead
                ? base64_encode($tag)
                : '';

            /*
             * CBC does not provide authentication itself, so authenticate
             * the IV and ciphertext before accepting them during decryption.
             *
             * AES-GCM already provides authentication via its tag.
             */
            $mac = $this->aead
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
        } catch (EncryptException $exception) {
            throw $exception;
        } catch (Throwable $exception) {
            /*
             * Do not propagate OpenSSL, JSON, serialization or random-number
             * internals to callers.
             */
            throw new EncryptException(self::ENCRYPTION_ERROR);
        }
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
        try {
            $payload = $this->getJsonPayload($payload);

            $iv = $this->decodeBase64($payload['iv']);

            if ($iv === false || strlen($iv) !== $this->ivLength) {
                throw new DecryptException(self::DECRYPTION_ERROR);
            }

            $tag = $this->decodeAndValidateTag($payload);

            $decrypted = $this->aead
                ? $this->decryptAead($payload, $iv, $tag)
                : $this->decryptAuthenticatedCbc($payload, $iv);

            if ($decrypted === false) {
                throw new DecryptException(self::DECRYPTION_ERROR);
            }

            if (! $unserialize) {
                return $decrypted;
            }

            return unserialize($decrypted);
        } catch (DecryptException $exception) {
            /*
             * Collapse all cryptographic validation failures into the same
             * externally observable error.
             */
            throw new DecryptException(self::DECRYPTION_ERROR);
        } catch (Throwable $exception) {
            throw new DecryptException(self::DECRYPTION_ERROR);
        }
    }

    /**
     * Decrypt an authenticated CBC payload.
     *
     * The MAC for every configured key is evaluated before decryption.
     *
     * @param  array  $payload
     * @param  string  $iv
     * @return string|false
     */
    private function decryptAuthenticatedCbc(
        array $payload,
        #[\SensitiveParameter] string $iv
    ) {
        $validKey = null;

        /*
         * Do not stop at the first MAC match. Evaluating all configured
         * keys reduces observable timing differences during key rotation.
         */
        foreach ($this->getAllKeys() as $key) {
            $validMac = $this->validMacForKey($payload, $key);

            if ($validMac && $validKey === null) {
                $validKey = $key;
            }
        }

        if ($validKey === null) {
            return false;
        }

        /*
         * Authentication is performed before CBC decryption. This is
         * important for avoiding padding-oracle style behavior.
         */
        return \openssl_decrypt(
            $payload['value'],
            $this->cipher,
            $validKey,
            0,
            $iv
        );
    }

    /**
     * Decrypt an AEAD payload using the current and legacy keys.
     *
     * @param  array  $payload
     * @param  string  $iv
     * @param  string  $tag
     * @return string|false
     */
    private function decryptAead(
        array $payload,
        #[\SensitiveParameter] string $iv,
        #[\SensitiveParameter] string $tag
    ) {
        $decrypted = false;

        /*
         * Attempt every configured key instead of returning immediately.
         * Besides making key rotation easier to reason about, this reduces
         * timing differences associated with the key's array position.
         */
        foreach ($this->getAllKeys() as $key) {
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

        return $decrypted;
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
            throw new DecryptException(self::DECRYPTION_ERROR);
        }

        $decoded = base64_decode($payload, true);

        if ($decoded === false) {
            throw new DecryptException(self::DECRYPTION_ERROR);
        }

        try {
            $payload = json_decode(
                $decoded,
                true,
                512,
                JSON_THROW_ON_ERROR
            );
        } catch (JsonException $exception) {
            throw new DecryptException(self::DECRYPTION_ERROR);
        }

        if (! $this->validPayload($payload)) {
            throw new DecryptException(self::DECRYPTION_ERROR);
        }

        return $payload;
    }

    /**
     * Verify that the encryption payload is structurally valid.
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

        if ($iv === false || strlen($iv) !== $this->ivLength) {
            return false;
        }

        /*
         * CBC payloads carry a SHA-256 HMAC represented as 64 hexadecimal
         * characters. Validate its shape before cryptographic comparison.
         */
        if (! $this->aead) {
            return strlen($payload['mac']) === 64
                && ctype_xdigit($payload['mac']);
        }

        /*
         * GCM uses an authentication tag rather than the separate MAC field.
         */
        return isset($payload['tag'])
            && $payload['tag'] !== '';
    }

    /**
     * Determine if the MAC is valid for the primary key.
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
     * Determine if the MAC is valid for the given key.
     *
     * hash_equals() performs timing-safe string comparison.
     *
     * @param  array  $payload
     * @param  string  $key
     * @return bool
     */
    protected function validMacForKey(
        #[\SensitiveParameter] $payload,
        #[\SensitiveParameter] $key
    ) {
        return hash_equals(
            $this->hash(
                $payload['iv'],
                $payload['value'],
                $key
            ),
            $payload['mac']
        );
    }

    /**
     * Decode and validate the AEAD authentication tag.
     *
     * @param  array  $payload
     * @return string
     *
     * @throws \Illuminate\Contracts\Encryption\DecryptException
     */
    private function decodeAndValidateTag(array $payload)
    {
        $encodedTag = $payload['tag'] ?? '';

        if (! $this->aead) {
            /*
             * A CBC payload must not contain an AEAD tag.
             */
            if ($encodedTag !== '') {
                throw new DecryptException(self::DECRYPTION_ERROR);
            }

            return '';
        }

        $tag = $this->decodeBase64($encodedTag);

        if (
            $tag === false
            || strlen($tag) !== self::GCM_TAG_LENGTH
        ) {
            throw new DecryptException(self::DECRYPTION_ERROR);
        }

        return $tag;
    }

    /**
     * Strict Base64 decoding helper.
     *
     * @param  string  $value
     * @return string|false
     */
    private function decodeBase64($value)
    {
        if (! is_string($value)) {
            return false;
        }

        return base64_decode($value, true);
    }

    /**
     * Ensure the given tag is valid for the selected cipher.
     *
     * Retained for compatibility with subclasses relying on this method.
     *
     * @param  string|null  $tag
     * @return void
     *
     * @throws \Illuminate\Contracts\Encryption\DecryptException
     */
    protected function ensureTagIsValid($tag)
    {
        if (
            $this->aead
            && (! is_string($tag) || strlen($tag) !== self::GCM_TAG_LENGTH)
        ) {
            throw new DecryptException(self::DECRYPTION_ERROR);
        }

        if (! $this->aead && is_string($tag)) {
            throw new DecryptException(self::DECRYPTION_ERROR);
        }
    }

    /**
     * Determine if the MAC must be independently validated.
     *
     * @return bool
     */
    protected function shouldValidateMac()
    {
        return ! $this->aead;
    }

    /**
     * Determine if the value appears to contain an encrypted payload.
     *
     * This performs structural detection only. It does NOT authenticate
     * the payload and therefore must never replace decrypt().
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
        } catch (JsonException $exception) {
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
     * Get the currently configured encryption key.
     *
     * Avoid logging, dumping or exposing this value.
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
     * @return array<int, string>
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
     * @return array<int, string>
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
            if (
                ! is_string($key)
                || ! static::supported($key, $this->cipher)
            ) {
                throw new RuntimeException(self::CONFIGURATION_ERROR);
            }
        }

        $this->previousKeys = array_values($keys);

        return $this;
    }

    /**
     * Normalize a cipher name once at the application boundary.
     *
     * @param  mixed  $cipher
     * @return string
     */
    private static function normalizeCipher($cipher)
    {
        return strtolower((string) $cipher);
    }
}
