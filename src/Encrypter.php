<?php

namespace Illuminate\Encryption;

use Illuminate\Contracts\Encryption\DecryptException;
use Illuminate\Contracts\Encryption\Encrypter as EncrypterContract;
use Illuminate\Contracts\Encryption\EncryptException;
use Illuminate\Contracts\Encryption\StringEncrypter;
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
     * @throws \RuntimeException
     */
    public function __construct(
        #[\SensitiveParameter] $key,
        $cipher = 'aes-128-cbc'
    ) {
        $key = (string) $key;
        $cipher = strtolower((string) $cipher);

        if (! static::supported($key, $cipher)) {
            // Deliberately generic: do not expose expected key size,
            // supplied key characteristics or internal configuration.
            throw new RuntimeException('Invalid encryption configuration.');
        }

        $this->key = $key;
        $this->cipher = $cipher;
    }

    /**
     * Determine if the given key and cipher combination is valid.
     */
    public static function supported(
        #[\SensitiveParameter] $key,
        $cipher
    ) {
        $cipher = strtolower((string) $cipher);

        if (! isset(self::$supportedCiphers[$cipher])) {
            return false;
        }

        return strlen((string) $key) === self::$supportedCiphers[$cipher]['size'];
    }

    /**
     * Create a new encryption key for the given cipher.
     */
    public static function generateKey($cipher)
    {
        $cipher = strtolower((string) $cipher);

        /*
         * random_bytes() uses a cryptographically secure random source.
         *
         * Do not silently generate a generic-length key for an unsupported
         * cipher, since that could hide a configuration error.
         */
        if (! isset(self::$supportedCiphers[$cipher])) {
            throw new RuntimeException('Invalid encryption configuration.');
        }

        return random_bytes(self::$supportedCiphers[$cipher]['size']);
    }

    /**
     * Encrypt the given value.
     *
     * @throws \Illuminate\Contracts\Encryption\EncryptException
     */
    public function encrypt(
        #[\SensitiveParameter] $value,
        $serialize = true
    ) {
        $cipher = strtolower($this->cipher);
        $ivLength = openssl_cipher_iv_length($cipher);

        if (! is_int($ivLength) || $ivLength <= 0) {
            throw new EncryptException('Could not encrypt the data.');
        }

        /*
         * CWE-329 / CWE-330:
         * Generate a fresh, unpredictable IV for every encryption operation.
         */
        try {
            $iv = random_bytes($ivLength);
        } catch (\Throwable $e) {
            /*
             * Do not chain the original exception because its details could
             * subsequently reach logs or exception renderers.
             */
            throw new EncryptException('Could not encrypt the data.');
        }

        $tag = '';

        try {
            $plainText = $serialize ? serialize($value) : $value;

            $encrypted = \openssl_encrypt(
                $plainText,
                $cipher,
                $this->key,
                0,
                $iv,
                $tag
            );
        } catch (\Throwable $e) {
            throw new EncryptException('Could not encrypt the data.');
        }

        if ($encrypted === false) {
            throw new EncryptException('Could not encrypt the data.');
        }

        $encodedIv = base64_encode($iv);
        $encodedTag = base64_encode($tag);

        /*
         * CBC is not authenticated encryption.
         *
         * Apply Encrypt-then-MAC:
         *
         *     HMAC-SHA-256(encoded-IV || ciphertext, key)
         *
         * The MAC will be checked in constant time BEFORE CBC decryption.
         *
         * GCM already authenticates the ciphertext through its authentication
         * tag, therefore a second MAC is not required for AEAD modes.
         */
        $mac = $this->isAead()
            ? ''
            : $this->hash($encodedIv, $encrypted, $this->key);

        $json = json_encode(
            [
                'iv' => $encodedIv,
                'value' => $encrypted,
                'mac' => $mac,
                'tag' => $encodedTag,
            ],
            JSON_UNESCAPED_SLASHES
        );

        if ($json === false || json_last_error() !== JSON_ERROR_NONE) {
            throw new EncryptException('Could not encrypt the data.');
        }

        return base64_encode($json);
    }

    /**
     * Encrypt a string without serialization.
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
     * @throws \Illuminate\Contracts\Encryption\DecryptException
     */
    public function decrypt(
        #[\SensitiveParameter] $payload,
        $unserialize = true
    ) {
        /*
         * Never expose whether the failure happened because of:
         *
         * - Base64;
         * - JSON;
         * - IV;
         * - tag;
         * - MAC;
         * - key rotation;
         * - padding;
         * - OpenSSL;
         * - unserialization.
         *
         * Externally all cryptographic failures have the same message.
         */
        try {
            $payload = $this->getJsonPayload($payload);

            $iv = base64_decode($payload['iv'], true);

            if ($iv === false) {
                throw new DecryptException('Could not decrypt the data.');
            }

            $tag = $this->decodeTag($payload);

            /*
             * For CBC, authenticate ciphertext BEFORE attempting
             * openssl_decrypt().
             *
             * This ordering is security-critical: it prevents unauthenticated
             * ciphertext from reaching the CBC padding/decryption operation.
             */
            if ($this->shouldValidateMac()) {
                return $this->decryptAuthenticatedPayload(
                    $payload,
                    $iv,
                    $unserialize
                );
            }

            /*
             * AEAD path.
             *
             * Each possible rotation key is attempted with OpenSSL's
             * authentication-tag verification.
             */
            foreach ($this->getAllKeys() as $key) {
                $decrypted = \openssl_decrypt(
                    $payload['value'],
                    strtolower($this->cipher),
                    $key,
                    0,
                    $iv,
                    $tag
                );

                if ($decrypted !== false) {
                    return $unserialize
                        ? unserialize($decrypted)
                        : $decrypted;
                }
            }
        } catch (DecryptException $e) {
            /*
             * Collapse all internal DecryptException variants into a
             * single public error.
             */
        } catch (\Throwable $e) {
            /*
             * Do not propagate or chain OpenSSL/JSON/serialization errors.
             */
        }

        throw new DecryptException('Could not decrypt the data.');
    }

    /**
     * Decrypt a non-AEAD payload using Encrypt-then-MAC.
     *
     * The HMAC MUST be successfully authenticated before openssl_decrypt()
     * receives the ciphertext.
     *
     * @param array $payload
     * @param string $iv
     * @param bool $unserialize
     * @return mixed
     *
     * @throws \Illuminate\Contracts\Encryption\DecryptException
     */
    protected function decryptAuthenticatedPayload(
        #[\SensitiveParameter] array $payload,
        #[\SensitiveParameter] string $iv,
        $unserialize
    ) {
        $validKey = null;

        /*
         * Check all rotation keys first.
         *
         * At this point NO CBC decryption has occurred.
         */
        foreach ($this->getAllKeys() as $key) {
            if ($this->validMacForKey($payload, $key)) {
                $validKey = $key;
                break;
            }
        }

        if ($validKey === null) {
            throw new DecryptException('Could not decrypt the data.');
        }

        /*
         * Only authenticated ciphertext reaches openssl_decrypt().
         */
        $decrypted = \openssl_decrypt(
            $payload['value'],
            strtolower($this->cipher),
            $validKey,
            0,
            $iv
        );

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
     * @throws \Illuminate\Contracts\Encryption\DecryptException
     */
    public function decryptString(
        #[\SensitiveParameter] $payload
    ) {
        return $this->decrypt($payload, false);
    }

    /**
     * Create a MAC for the given value.
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
     * @throws \Illuminate\Contracts\Encryption\DecryptException
     */
    protected function getJsonPayload(
        #[\SensitiveParameter] $payload
    ) {
        if (! is_string($payload)) {
            throw new DecryptException('Could not decrypt the data.');
        }

        /*
         * Strict Base64 decoding prevents malformed encodings from being
         * silently accepted.
         */
        $decoded = base64_decode($payload, true);

        if ($decoded === false) {
            throw new DecryptException('Could not decrypt the data.');
        }

        $decodedPayload = json_decode($decoded, true);

        if (
            json_last_error() !== JSON_ERROR_NONE ||
            ! $this->validPayload($decodedPayload)
        ) {
            throw new DecryptException('Could not decrypt the data.');
        }

        return $decodedPayload;
    }

    /**
     * Verify that the encryption payload is valid.
     */
    protected function validPayload(
        #[\SensitiveParameter] $payload
    ) {
        if (! is_array($payload)) {
            return false;
        }

        /*
         * Require exactly the types expected by the cryptographic routines.
         */
        foreach (['iv', 'value', 'mac'] as $item) {
            if (
                ! array_key_exists($item, $payload) ||
                ! is_string($payload[$item])
            ) {
                return false;
            }
        }

        if (
            array_key_exists('tag', $payload) &&
            ! is_string($payload['tag'])
        ) {
            return false;
        }

        $iv = base64_decode($payload['iv'], true);

        if ($iv === false) {
            return false;
        }

        $expectedIvLength = openssl_cipher_iv_length(
            strtolower($this->cipher)
        );

        if (
            ! is_int($expectedIvLength) ||
            strlen($iv) !== $expectedIvLength
        ) {
            return false;
        }

        /*
         * HMAC-SHA-256 is represented by exactly 64 hexadecimal characters
         * when binary=false (the hash_hmac default).
         *
         * For AEAD, Laravel's existing payload representation uses an empty
         * MAC because authentication is supplied by the tag.
         */
        if ($this->shouldValidateMac()) {
            if (
                strlen($payload['mac']) !== 64 ||
                ! ctype_xdigit($payload['mac'])
            ) {
                return false;
            }
        } elseif ($payload['mac'] !== '') {
            return false;
        }

        return true;
    }

    /**
     * Decode and validate the authentication tag.
     *
     * @throws \Illuminate\Contracts\Encryption\DecryptException
     */
    protected function decodeTag(
        #[\SensitiveParameter] array $payload
    ) {
        $encodedTag = $payload['tag'] ?? '';

        if (! is_string($encodedTag)) {
            throw new DecryptException('Could not decrypt the data.');
        }

        /*
         * CBC payloads must not carry an AEAD authentication tag.
         */
        if (! $this->isAead()) {
            if ($encodedTag !== '') {
                throw new DecryptException('Could not decrypt the data.');
            }

            return '';
        }

        $tag = base64_decode($encodedTag, true);

        /*
         * OpenSSL GCM commonly uses a 128-bit / 16-byte authentication tag.
         * Enforce the expected application format rather than accepting
         * malformed/truncated tags.
         */
        if ($tag === false || strlen($tag) !== 16) {
            throw new DecryptException('Could not decrypt the data.');
        }

        return $tag;
    }

    /**
     * Determine if the MAC for the given payload is valid for the primary key.
     */
    protected function validMac(
        #[\SensitiveParameter] array $payload
    ) {
        return $this->validMacForKey(
            $payload,
            $this->key
        );
    }

    /**
     * Determine if the MAC is valid for the given payload and key.
     */
    protected function validMacForKey(
        #[\SensitiveParameter] $payload,
        #[\SensitiveParameter] $key
    ) {
        /*
         * Validate basic shape before hash_equals() so malformed attacker
         * input never causes an avoidable type/length problem.
         */
        if (
            ! is_array($payload) ||
            ! isset($payload['iv'], $payload['value'], $payload['mac']) ||
            ! is_string($payload['iv']) ||
            ! is_string($payload['value']) ||
            ! is_string($payload['mac'])
        ) {
            return false;
        }

        $expectedMac = $this->hash(
            $payload['iv'],
            $payload['value'],
            $key
        );

        /*
         * Constant-time comparison prevents leaking useful information
         * through ordinary string-comparison timing.
         */
        return hash_equals(
            $expectedMac,
            $payload['mac']
        );
    }

    /**
     * Ensure the given tag is valid for the selected cipher.
     *
     * Retained for API/internal compatibility.
     *
     * @throws \Illuminate\Contracts\Encryption\DecryptException
     */
    protected function ensureTagIsValid(
        #[\SensitiveParameter] $tag
    ) {
        if ($this->isAead()) {
            if (! is_string($tag) || strlen($tag) !== 16) {
                throw new DecryptException('Could not decrypt the data.');
            }

            return;
        }

        if ($tag !== null && $tag !== '') {
            throw new DecryptException('Could not decrypt the data.');
        }
    }

    /**
     * Determine if the selected cipher is AEAD.
     */
    protected function isAead()
    {
        return self::$supportedCiphers[
            strtolower($this->cipher)
        ]['aead'];
    }

    /**
     * Determine if we should validate the MAC while decrypting.
     */
    protected function shouldValidateMac()
    {
        return ! $this->isAead();
    }

    /**
     * Determine if the given value appears to be encrypted by this encrypter.
     *
     * This performs structural detection only and MUST NOT be treated as
     * cryptographic authentication.
     */
    public static function appearsEncrypted(
        #[\SensitiveParameter] $value
    ) {
        if (! is_string($value)) {
            return false;
        }

        $decoded = base64_decode($value, true);

        if ($decoded === false) {
            return false;
        }

        $payload = json_decode($decoded, true);

        if (
            json_last_error() !== JSON_ERROR_NONE ||
            ! is_array($payload)
        ) {
            return false;
        }

        return isset(
            $payload['iv'],
            $payload['value'],
            $payload['mac']
        )
            && is_string($payload['iv'])
            && is_string($payload['value'])
            && is_string($payload['mac']);
    }

    /**
     * Get the encryption key that the encrypter is currently using.
     *
     * WARNING:
     * This method intentionally exposes key material because it is part of
     * the existing public API. Callers must treat its return value as secret.
     */
    public function getKey()
    {
        return $this->key;
    }

    /**
     * Get the current encryption key and all previous encryption keys.
     */
    public function getAllKeys()
    {
        return [$this->key, ...$this->previousKeys];
    }

    /**
     * Get the previous encryption keys.
     */
    public function getPreviousKeys()
    {
        return $this->previousKeys;
    }

    /**
     * Set previous / legacy encryption keys.
     *
     * @throws \RuntimeException
     */
    public function previousKeys(
        #[\SensitiveParameter] array $keys
    ) {
        foreach ($keys as $key) {
            if (! static::supported($key, $this->cipher)) {
                /*
                 * Do not disclose expected length, actual length,
                 * configured cipher or any key characteristics.
                 */
                throw new RuntimeException(
                    'Invalid encryption configuration.'
                );
            }
        }

        $this->previousKeys = $keys;

        return $this;
    }
}
