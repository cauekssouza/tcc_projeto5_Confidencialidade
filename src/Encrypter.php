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
     * Generic errors deliberately avoid exposing cryptographic internals.
     */
    private const ENCRYPTION_ERROR = 'Could not encrypt the data.';
    private const DECRYPTION_ERROR = 'Could not decrypt the data.';
    private const CONFIGURATION_ERROR = 'Invalid encryption configuration.';

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
     * @throws \RuntimeException
     */
    public function __construct(
        #[\SensitiveParameter] $key,
        $cipher = 'aes-128-cbc'
    ) {
        $key = (string) $key;
        $cipher = strtolower((string) $cipher);

        if (! static::supported($key, $cipher)) {
            /*
             * Do not disclose expected key lengths, supported algorithms
             * or any other cryptographic configuration details.
             */
            throw new RuntimeException(self::CONFIGURATION_ERROR);
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

        return mb_strlen((string) $key, '8bit')
            === self::$supportedCiphers[$cipher]['size'];
    }

    /**
     * Create a new encryption key for the given cipher.
     */
    public static function generateKey($cipher)
    {
        $cipher = strtolower((string) $cipher);

        /*
         * random_bytes() is a cryptographically secure source.
         */
        return random_bytes(
            self::$supportedCiphers[$cipher]['size'] ?? 32
        );
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
            $cipher = strtolower($this->cipher);
            $ivLength = openssl_cipher_iv_length($cipher);

            if (! is_int($ivLength) || $ivLength <= 0) {
                throw new EncryptException(self::ENCRYPTION_ERROR);
            }

            /*
             * CWE-329 / CWE-330:
             * IV generated from a cryptographically secure random source.
             */
            $iv = random_bytes($ivLength);

            /*
             * Serialization occurs only in local memory and its result
             * is immediately passed to the cipher.
             */
            $plaintext = $serialize
                ? serialize($value)
                : (string) $value;

            $tag = null;

            if ($this->isAead()) {
                $encrypted = \openssl_encrypt(
                    $plaintext,
                    $cipher,
                    $this->key,
                    0,
                    $iv,
                    $tag
                );
            } else {
                /*
                 * CBC does not use an AEAD authentication tag.
                 */
                $encrypted = \openssl_encrypt(
                    $plaintext,
                    $cipher,
                    $this->key,
                    0,
                    $iv
                );
            }

            if ($encrypted === false) {
                throw new EncryptException(self::ENCRYPTION_ERROR);
            }

            $encodedIv = base64_encode($iv);
            $encodedTag = $this->isAead()
                ? base64_encode($tag ?? '')
                : '';

            /*
             * Encrypt-then-MAC:
             *
             * For non-AEAD ciphers, authenticate the encrypted
             * representation BEFORE constructing / serializing the
             * external payload.
             *
             * This preserves compatibility with Laravel's payload:
             * HMAC-SHA256(base64(iv) || ciphertext, key).
             */
            $mac = $this->shouldValidateMac()
                ? $this->hash(
                    $encodedIv,
                    $encrypted,
                    $this->key
                )
                : '';

            $payload = [
                'iv' => $encodedIv,
                'value' => $encrypted,
                'mac' => $mac,
                'tag' => $encodedTag,
            ];

            $json = json_encode(
                $payload,
                JSON_UNESCAPED_SLASHES
            );

            if ($json === false || json_last_error() !== JSON_ERROR_NONE) {
                throw new EncryptException(self::ENCRYPTION_ERROR);
            }

            return base64_encode($json);
        } catch (EncryptException $e) {
            throw $e;
        } catch (\Throwable $e) {
            /*
             * Deliberately discard the original exception message from
             * the public cryptographic boundary.
             *
             * Do not include $e as the previous exception because
             * exception renderers/loggers may recursively expose details
             * from the underlying OpenSSL/runtime failure.
             */
            throw new EncryptException(self::ENCRYPTION_ERROR);
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
     * Authentication is performed before CBC decryption.
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
                throw new DecryptException(self::DECRYPTION_ERROR);
            }

            $tag = null;

            if ($payload['tag'] !== '') {
                $tag = base64_decode($payload['tag'], true);

                if ($tag === false) {
                    throw new DecryptException(self::DECRYPTION_ERROR);
                }
            }

            $this->ensureTagIsValid($tag);

            $decrypted = false;

            /*
             * CBC / non-AEAD:
             *
             * Authenticate ciphertext BEFORE attempting decryption.
             * This is essential to Encrypt-then-MAC.
             */
            if ($this->shouldValidateMac()) {
                $validKey = null;

                foreach ($this->getAllKeys() as $key) {
                    if (
                        $this->validMacForKey($payload, $key)
                        && $validKey === null
                    ) {
                        $validKey = $key;
                    }
                }

                /*
                 * Deliberately do not disclose whether the failure was
                 * caused by an invalid MAC, wrong key or corrupted data.
                 */
                if ($validKey === null) {
                    throw new DecryptException(
                        self::DECRYPTION_ERROR
                    );
                }

                $decrypted = \openssl_decrypt(
                    $payload['value'],
                    strtolower($this->cipher),
                    $validKey,
                    0,
                    $iv
                );
            } else {
                /*
                 * AEAD:
                 * OpenSSL verifies the authentication tag as part of
                 * openssl_decrypt().
                 */
                foreach ($this->getAllKeys() as $key) {
                    $candidate = \openssl_decrypt(
                        $payload['value'],
                        strtolower($this->cipher),
                        $key,
                        0,
                        $iv,
                        $tag ?? ''
                    );

                    if ($candidate !== false) {
                        $decrypted = $candidate;
                        break;
                    }
                }
            }

            if ($decrypted === false) {
                throw new DecryptException(
                    self::DECRYPTION_ERROR
                );
            }

            return $unserialize
                ? unserialize($decrypted)
                : $decrypted;
        } catch (DecryptException $e) {
            /*
             * Normalize every externally observable decryption error.
             */
            throw new DecryptException(
                self::DECRYPTION_ERROR
            );
        } catch (\Throwable $e) {
            /*
             * Do not propagate internal parser/OpenSSL/runtime errors.
             */
            throw new DecryptException(
                self::DECRYPTION_ERROR
            );
        }
    }

    /**
     * Decrypt the given string without unserialization.
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
            throw new DecryptException(
                self::DECRYPTION_ERROR
            );
        }

        /*
         * Strict Base64 decoding rejects malformed input rather than
         * silently accepting invalid characters.
         */
        $decoded = base64_decode($payload, true);

        if ($decoded === false) {
            throw new DecryptException(
                self::DECRYPTION_ERROR
            );
        }

        $decodedPayload = json_decode($decoded, true);

        if (
            json_last_error() !== JSON_ERROR_NONE
            || ! $this->validPayload($decodedPayload)
        ) {
            throw new DecryptException(
                self::DECRYPTION_ERROR
            );
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

        foreach (['iv', 'value', 'mac'] as $item) {
            if (
                ! isset($payload[$item])
                || ! is_string($payload[$item])
            ) {
                return false;
            }
        }

        if (
            isset($payload['tag'])
            && ! is_string($payload['tag'])
        ) {
            return false;
        }

        /*
         * Normalize legacy payloads without a tag.
         */
        $payload['tag'] ??= '';

        $iv = base64_decode($payload['iv'], true);

        if ($iv === false) {
            return false;
        }

        $expectedLength = openssl_cipher_iv_length(
            strtolower($this->cipher)
        );

        return is_int($expectedLength)
            && strlen($iv) === $expectedLength;
    }

    /**
     * Determine if the MAC for the payload is valid for the primary key.
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
        if (
            ! isset(
                $payload['iv'],
                $payload['value'],
                $payload['mac']
            )
            || ! is_string($payload['mac'])
        ) {
            return false;
        }

        $expectedMac = $this->hash(
            $payload['iv'],
            $payload['value'],
            $key
        );

        /*
         * Constant-time comparison prevents timing disclosure of the
         * expected authentication code.
         */
        return hash_equals(
            $expectedMac,
            $payload['mac']
        );
    }

    /**
     * Ensure the authentication tag is valid for the selected cipher.
     */
    protected function ensureTagIsValid(
        #[\SensitiveParameter] $tag
    ) {
        if ($this->isAead()) {
            if (! is_string($tag) || strlen($tag) !== 16) {
                throw new DecryptException(
                    self::DECRYPTION_ERROR
                );
            }

            return;
        }

        /*
         * A CBC payload must not contain an AEAD tag.
         * The external error deliberately does not reveal that fact.
         */
        if ($tag !== null) {
            throw new DecryptException(
                self::DECRYPTION_ERROR
            );
        }
    }

    /**
     * Determine whether the active cipher is AEAD.
     */
    protected function isAead()
    {
        return self::$supportedCiphers[
            strtolower($this->cipher)
        ]['aead'];
    }

    /**
     * Determine if a separate MAC must be validated.
     */
    protected function shouldValidateMac()
    {
        return ! $this->isAead();
    }

    /**
     * Determine if the value appears to be encrypted.
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

        $payload = json_decode($decoded, true);

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
     * WARNING: callers must treat the returned value as secret.
     */
    public function getKey()
    {
        return $this->key;
    }

    /**
     * Get the current and previous keys.
     *
     * WARNING: callers must treat all returned values as secrets.
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
                 * Do not disclose valid key sizes, the supplied key,
                 * cipher list or which key failed validation.
                 */
                throw new RuntimeException(
                    self::CONFIGURATION_ERROR
                );
            }
        }

        $this->previousKeys = $keys;

        return $this;
    }
}
