<?php

declare(strict_types=1);

namespace Illuminate\Encryption;

use Illuminate\Contracts\Encryption\DecryptException;
use Illuminate\Contracts\Encryption\Encrypter as EncrypterContract;
use Illuminate\Contracts\Encryption\EncryptException;
use Illuminate\Contracts\Encryption\StringEncrypter;
use RuntimeException;

class Encrypter implements EncrypterContract, StringEncrypter
{
    private const SUPPORTED_CIPHERS = [
        'aes-128-cbc' => ['size' => 16, 'aead' => false],
        'aes-256-cbc' => ['size' => 32, 'aead' => false],
        'aes-128-gcm' => ['size' => 16, 'aead' => true],
        'aes-256-gcm' => ['size' => 32, 'aead' => true],
    ];

    public function __construct(
        #[\SensitiveParameter]
        private readonly string $key,
        private readonly string $cipher = 'aes-128-cbc'
    ) {
        if (! self::supported($key, $cipher)) {
            $supported = implode(', ', array_keys(self::SUPPORTED_CIPHERS));
            throw new RuntimeException("Unsupported cipher or incorrect key length. Supported ciphers are: {$supported}.");
        }
    }

    private array $previousKeys = [];

    public static function supported(string $key, string $cipher): bool
    {
        $cipher = strtolower($cipher);

        return isset(self::SUPPORTED_CIPHERS[$cipher])
            && mb_strlen($key, '8bit') === self::SUPPORTED_CIPHERS[$cipher]['size'];
    }

    public static function generateKey(string $cipher): string
    {
        $cipher = strtolower($cipher);
        return random_bytes(self::SUPPORTED_CIPHERS[$cipher]['size'] ?? 32);
    }

    public function encrypt(#[\SensitiveParameter] mixed $value, bool $serialize = true): string
    {
        $cipher = strtolower($this->cipher);
        $iv = random_bytes(openssl_cipher_iv_length($cipher));

        $encrypted = openssl_encrypt(
            $serialize ? serialize($value) : $value,
            $cipher,
            $this->key,
            options: 0,
            iv: $iv,
            tag: $tag
        );

        if ($encrypted === false) {
            throw new EncryptException('Could not encrypt the data.');
        }

        $payload = [
            'iv'    => base64_encode($iv),
            'value' => $encrypted,
            'tag'   => base64_encode($tag ?? ''),
            'mac'   => self::SUPPORTED_CIPHERS[$cipher]['aead']
                ? ''
                : $this->hash(base64_encode($iv), $encrypted, $this->key),
        ];

        $json = json_encode($payload, JSON_UNESCAPED_SLASHES);

        if (json_last_error() !== JSON_ERROR_NONE) {
            throw new EncryptException('Could not encrypt the data.');
        }

        return base64_encode($json);
    }

    public function encryptString(#[\SensitiveParameter] string $value): string
    {
        return $this->encrypt($value, false);
    }

    public function decrypt(string $payload, bool $unserialize = true): mixed
    {
        $payload = $this->getJsonPayload($payload);
        $cipher  = strtolower($this->cipher);

        $iv  = base64_decode($payload['iv']);
        $tag = empty($payload['tag']) ? null : base64_decode($payload['tag']);

        $this->ensureTagIsValid($tag);

        $keys = $this->getAllKeys();
        $validKey = null;

        foreach ($keys as $key) {
            if ($this->shouldValidateMac()) {
                if ($this->validMacForKey($payload, $key)) {
                    $validKey ??= $key;
                }
                continue;
            }

            $decrypted = openssl_decrypt($payload['value'], $cipher, $key, 0, $iv, $tag ?? '');
            if ($decrypted !== false) {
                break;
            }
        }

        if ($this->shouldValidateMac()) {
            if ($validKey === null) {
                throw new DecryptException('The MAC is invalid.');
            }

            $decrypted = openssl_decrypt($payload['value'], $cipher, $validKey, 0, $iv, $tag ?? '');
        }

        if ($decrypted === false) {
            throw new DecryptException('Could not decrypt the data.');
        }

        return $unserialize ? unserialize($decrypted) : $decrypted;
    }

    public function decryptString(string $payload): string
    {
        return $this->decrypt($payload, false);
    }

    protected function hash(string $iv, string $value, string $key): string
    {
        return hash_hmac('sha256', $iv . $value, $key);
    }

    protected function getJsonPayload(string $payload): array
    {
        $decoded = json_decode(base64_decode($payload), true);

        if (! $this->validPayload($decoded)) {
            throw new DecryptException('The payload is invalid.');
        }

        return $decoded;
    }

    protected function validPayload(mixed $payload): bool
    {
        if (! is_array($payload)) {
            return false;
        }

        foreach (['iv', 'value', 'mac'] as $key) {
            if (! isset($payload[$key]) || ! is_string($payload[$key])) {
                return false;
            }
        }

        if (isset($payload['tag']) && ! is_string($payload['tag'])) {
            return false;
        }

        return strlen(base64_decode($payload['iv'], true)) === openssl_cipher_iv_length(strtolower($this->cipher));
    }

    protected function validMacForKey(array $payload, string $key): bool
    {
        return hash_equals(
            $this->hash($payload['iv'], $payload['value'], $key),
            $payload['mac']
        );
    }

    protected function ensureTagIsValid(?string $tag): void
    {
        $cipher = strtolower($this->cipher);
        $isAead = self::SUPPORTED_CIPHERS[$cipher]['aead'];

        if ($isAead && strlen($tag ?? '') !== 16) {
            throw new DecryptException('Could not decrypt the data.');
        }

        if (! $isAead && is_string($tag)) {
            throw new DecryptException('Unable to use tag because the cipher algorithm does not support AEAD.');
        }
    }

    protected function shouldValidateMac(): bool
    {
        return ! self::SUPPORTED_CIPHERS[strtolower($this->cipher)]['aead'];
    }

    public static function appearsEncrypted(mixed $value): bool
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
            && isset($payload['iv'], $payload['value'], $payload['mac']);
    }

    public function getKey(): string
    {
        return $this->key;
    }

    public function getAllKeys(): array
    {
        return [$this->key, ...$this->previousKeys];
    }

    public function getPreviousKeys(): array
    {
        return $this->previousKeys;
    }

    public function previousKeys(array $keys): self
    {
        foreach ($keys as $key) {
            if (! self::supported($key, $this->cipher)) {
                $supported = implode(', ', array_keys(self::SUPPORTED_CIPHERS));
                throw new RuntimeException("Unsupported cipher or incorrect key length. Supported ciphers are: {$supported}.");
            }
        }

        $this->previousKeys = $keys;
        return $this;
    }
}
