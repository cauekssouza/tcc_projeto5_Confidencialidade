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
     * @throws \RuntimeException
     */
    public function __construct(
        #[\SensitiveParameter] $key,
        $cipher = 'aes-128-cbc'
    ) {
        $key = (string) $key;
        $cipher = strtolower((string) $cipher);

        if (! static::supported($key, $cipher)) {
            // Intentionally generic: do not disclose key requirements
            // or internal cryptographic configuration.
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
     * Create a cryptographically secure encryption key.
     *
     * @throws \RuntimeException
     */
    public static function generateKey($cipher)
    {
        $cipher = strtolower((string) $cipher);

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
        try {
            $cipher = $this->cipher;
            $ivLength = openssl_cipher_iv_length($cipher);

            if (! is_int($ivLength) || $ivLength <= 0) {
                throw new EncryptException('Encryption operation failed.');
            }

            /*
             * CWE-329 / CWE-330:
             * Generate a fresh, cryptographically secure IV for every
             * encryption operation.
             */
            $iv = random_bytes($ivLength);

            $plaintext = $serialize
                ? serialize($value)
                : (string) $value;

            $tag = null;

            $encrypted = \openssl_encrypt(
                $plaintext,
                $cipher,
                $this->key,
                0,
                $iv,
                $tag
            );

            if ($encrypted === false) {
                throw new EncryptException('Encryption operation failed.');
            }

            $encodedIv = base64_encode($iv);
            $encodedTag = base64_encode($tag ?? '');

            /*
             * AES-CBC is not authenticated by itself.
             *
             * Authenticate IV + ciphertext BEFORE packaging the payload.
             * This implements Encrypt-then-MAC.
             *
             * GCM already provides authenticity through its authentication tag.
             */
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
            } catch (JsonException) {
                throw new EncryptException('Encryption operation failed.');
            }

            return base64_encode($json);
        } catch (EncryptException) {
            // Never propagate lower-level cryptographic details.
            throw new EncryptException('Encryption operation failed.');
        } catch (Throwable) {
            // Do not include the original exception as $previous because its
            // message/trace may disclose implementation details.
            throw new EncryptException('Encryption operation failed.');
        }
    }

    /**
     * Encrypt a string without serialization.
     */
    public function encryptString(
        #[\SensitiveParameter] $value
    ) {
        return $this->encrypt($value, false);
    }

    /**
     * Decrypt the given value.
     *
     * Authentication is always performed before plaintext is returned or
     * unserialized.
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
                throw new DecryptException('Decryption operation failed.');
            }

            $tag = null;

            if ($this->isAead()) {
                $tag = base64_decode($payload['tag'], true);

                $this->ensureTagIsValid($tag);
            }

            $keys = $this->getAllKeys();
            $decrypted = false;

            /*
             * Non-AEAD mode:
             *
             * Authenticate ciphertext before attempting decryption.
             * An invalid MAC never reaches openssl_decrypt().
             */
            if ($this->shouldValidateMac()) {
                $validKey = null;

                foreach ($keys as $key) {
                    if ($this->validMacForKey($payload, $key)) {
                        $validKey = $key;
                        break;
                    }
                }

                if ($validKey === null) {
                    throw new DecryptException('Decryption operation failed.');
                }

                $decrypted = \openssl_decrypt(
                    $payload['value'],
                    $this->cipher,
                    $validKey,
                    0,
                    $iv
                );
            } else {
                /*
                 * AEAD mode:
                 *
                 * openssl_decrypt() validates the GCM authentication tag.
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

                    if ($candidate !== false) {
                        $decrypted = $candidate;
                        break;
                    }
                }
            }

            if ($decrypted === false) {
                throw new DecryptException('Decryption operation failed.');
            }

            if (! $unserialize) {
                return $decrypted;
            }

            /*
             * The serialized representation is processed only after successful
             * cryptographic authentication.
             *
             * Suppress parser warnings so malformed internal representations
             * cannot leak parsing/structure information through PHP warnings.
             */
            try {
                return @unserialize($decrypted);
            } catch (Throwable) {
                throw new DecryptException('Decryption operation failed.');
            }
        } catch (DecryptException) {
            /*
             * Deliberately use exactly the same externally visible error for:
             * - malformed Base64
             * - malformed JSON
             * - invalid IV
             * - invalid MAC
             * - invalid GCM tag
             * - incorrect key
             * - OpenSSL failure
             * - unserialization failure
             *
             * This avoids exposing a cryptographic oracle.
             */
            throw new DecryptException('Decryption operation failed.');
        } catch (Throwable) {
            throw new DecryptException('Decryption operation failed.');
        }
    }

    /**
     * Decrypt a string without unserialization.
     */
    public function decryptString(
        #[\SensitiveParameter] $payload
    ) {
        return $this->decrypt($payload, false);
    }

    /**
     * Create an HMAC for IV + ciphertext.
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
     * Parse and validate the encrypted payload.
     *
     * @throws \Illuminate\Contracts\Encryption\DecryptException
     */
    protected function getJsonPayload(
        #[\SensitiveParameter] $payload
    ) {
        if (! is_string($payload)) {
            throw new DecryptException('Decryption operation failed.');
        }

        $decoded = base64_decode($payload, true);

        if ($decoded === false) {
            throw new DecryptException('Decryption operation failed.');
        }

        try {
            $decodedPayload = json_decode(
                $decoded,
                true,
                512,
                JSON_THROW_ON_ERROR
            );
        } catch (JsonException) {
            throw new DecryptException('Decryption operation failed.');
        }

        if (! $this->validPayload($decodedPayload)) {
            throw new DecryptException('Decryption operation failed.');
        }

        return $decodedPayload;
    }

    /**
     * Verify that the encryption payload is structurally valid.
     */
    protected function validPayload(
        #[\SensitiveParameter] $payload
    ) {
        if (! is_array($payload)) {
            return false;
        }

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

        /*
         * Reject unexpected fields.
         *
         * This keeps the wire format deterministic and reduces ambiguity
         * when processing attacker-controlled payloads.
         */
        $allowedKeys = ['iv', 'value', 'mac', 'tag'];

        foreach (array_keys($payload) as $key) {
            if (! in_array($key, $allowedKeys, true)) {
                return false;
            }
        }

        $iv = base64_decode($payload['iv'], true);

        if ($iv === false) {
            return false;
        }

        $expectedIvLength = openssl_cipher_iv_length($this->cipher);

        if (
            ! is_int($expectedIvLength) ||
            strlen($iv) !== $expectedIvLength
        ) {
            return false;
        }

        /*
         * openssl_encrypt() with options=0 returns Base64 ciphertext.
         * Validate its encoding before passing it to OpenSSL.
         */
        if (base64_decode($payload['value'], true) === false) {
            return false;
        }

        if ($this->isAead()) {
            if (
                ! array_key_exists('tag', $payload) ||
                $payload['mac'] !== ''
            ) {
                return false;
            }

            $tag = base64_decode($payload['tag'], true);

            return is_string($tag) && strlen($tag) === 16;
        }

        /*
         * CBC payloads must contain an HMAC-SHA-256 represented as
         * 64 hexadecimal characters and must not carry an AEAD tag.
         */
        if (
            strlen($payload['mac']) !== 64 ||
            ! ctype_xdigit($payload['mac'])
        ) {
            return false;
        }

        return ! isset($payload['tag']) || $payload['tag'] === '';
    }

    /**
     * Determine if the MAC is valid for the primary key.
     */
    protected function validMac(
        #[\SensitiveParameter] array $payload
    ) {
        return $this->validMacForKey($payload, $this->key);
    }

    /**
     * Determine if the MAC is valid for a given key.
     */
    protected function validMacForKey(
        #[\SensitiveParameter] $payload,
        #[\SensitiveParameter] $key
    ) {
        if (
            ! is_array($payload) ||
            ! isset($payload['iv'], $payload['value'], $payload['mac'])
        ) {
            return false;
        }

        $expected = $this->hash(
            $payload['iv'],
            $payload['value'],
            $key
        );

        /*
         * Constant-time comparison prevents timing-based MAC comparison.
         */
        return hash_equals($expected, $payload['mac']);
    }

    /**
     * Validate an AEAD authentication tag.
     *
     * @throws \Illuminate\Contracts\Encryption\DecryptException
     */
    protected function ensureTagIsValid(
        #[\SensitiveParameter] $tag
    ) {
        if (! $this->isAead()) {
            if ($tag !== null) {
                throw new DecryptException('Decryption operation failed.');
            }

            return;
        }

        if (! is_string($tag) || strlen($tag) !== 16) {
            throw new DecryptException('Decryption operation failed.');
        }
    }

    /**
     * Determine whether the selected cipher is AEAD.
     */
    protected function isAead()
    {
        return self::$supportedCiphers[$this->cipher]['aead'];
    }

    /**
     * Determine whether an independent MAC must be validated.
     */
    protected function shouldValidateMac()
    {
        return ! $this->isAead();
    }

    /**
     * Determine if a value has the basic encrypted-payload format.
     *
     * This method performs structural detection only. It does NOT establish
     * authenticity.
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

        try {
            $payload = json_decode(
                $decoded,
                true,
                512,
                JSON_THROW_ON_ERROR
            );
        } catch (JsonException) {
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
     * Get the encryption key currently in use.
     *
     * NOTE:
     * Retained only for compatibility with the existing public API.
     * Application code should avoid exposing or logging this value.
     */
    public function getKey()
    {
        return $this->key;
    }

    /**
     * Get the current and legacy encryption keys.
     *
     * Kept public for compatibility with the original API.
     */
    public function getAllKeys()
    {
        return [$this->key, ...$this->previousKeys];
    }

    /**
     * Get previous encryption keys.
     *
     * Kept public for compatibility with the original API.
     */
    public function getPreviousKeys()
    {
        return $this->previousKeys;
    }

    /**
     * Configure previous / legacy encryption keys.
     *
     * @throws \RuntimeException
     */
    public function previousKeys(
        #[\SensitiveParameter] array $keys
    ) {
        foreach ($keys as $key) {
            if (! static::supported($key, $this->cipher)) {
                /*
                 * Do not disclose expected length, supplied length,
                 * cipher internals, or any portion of the offending key.
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
