<?php

declare(strict_types=1);

namespace Illuminate\Encryption;

use Illuminate\Contracts\Encryption\DecryptException;
use Illuminate\Contracts\Encryption\Encrypter as EncrypterContract;
use Illuminate\Contracts\Encryption\EncryptException;
use Illuminate\Contracts\Encryption\StringEncrypter;
use RuntimeException;

final class Encrypter implements EncrypterContract, StringEncrypter
{
    private readonly string $key;
    private readonly string $cipher;

    /** @var string[] */
    private array $previousKeys = [];

    private const SUPPORTED_CIPHERS = [
        'aes-128-cbc' => ['size' => 16, 'aead' => false],
        'aes-256-cbc' => ['size' => 32, 'aead' => false],
        'aes-128-gcm' => ['size' => 16, 'aead' => true],
        'aes-256-gcm' => ['size' => 32, 'aead' => true],
    ];

    public function __construct(string $key, string $cipher = 'aes-128-cbc')
    {
        $cipher = strtolower($cipher);

        if (!self::supported($key, $cipher)) {
            $supported = implode(', ', array_keys(self::SUPPORTED_CIPHERS));
            throw new RuntimeException("Unsupported cipher or incorrect key length. Supported ciphers are: {$supported}.");
        }

        $this->key = $key;
        $this->cipher = $cipher;
    }

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

    public function encrypt(mixed $value, bool $serialize = true): string
    {
        $ivLength = openssl_cipher_iv_length($this->cipher);
        $iv = random_bytes($ivLength);

        $payload = $serialize ? serialize($value) : $value;

        $tag = '';
        $encrypted = openssl_encrypt(
            $payload,
            $this->cipher,
            $this->key,
            options: 0,
            iv: $iv,
            tag: $tag
        );

        if ($encrypted === false) {
            throw new EncryptException('Could not encrypt the data.');
        }

        $encodedIv = base64_encode($iv);
        $encodedTag = base64_encode($tag);

        $mac = $this->isAead()
            ? ''
            : $this->hash($encodedIv, $encrypted, $this->key);

        $json = json_encode([
            'iv'    => $encodedIv,
            'value' => $encrypted,
            'mac'   => $mac,
            'tag'   => $encodedTag,
        ], JSON_UNESCAPED_SLASHES);

        if ($json === false) {
            throw new EncryptException('Could not encrypt the data.');
        }

        return base64_encode($json);
    }

    public function encryptString(string $value): string
    {
        return $this->encrypt($value, false);
    }

    public function decrypt(string $payload, bool $unserialize = true): mixed
    {
        $payload = $this->getJsonPayload($payload);

        $iv = base64_decode($payload['iv']);
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

            $decrypted = openssl_decrypt(
                $payload['value'],
                $this->cipher,
                $key,
                options: 0,
                iv: $iv,
                tag: $tag ?? ''
            );

            if ($decrypted !== false) {
                break;
            }
        }

        if ($this->shouldValidateMac() && $validKey === null) {
            throw new DecryptException('The MAC is invalid.');
        }

        $finalKey = $validKey ?? $key;

        $decrypted = openssl_decrypt(
            $payload['value'],
            $this->cipher,
            $finalKey,
            options: 0,
            iv: $iv,
            tag: $tag ?? ''
        );

        if ($decrypted === false) {
            throw new DecryptException('Could not decrypt the data.');
        }

        return $unserialize ? unserialize($decrypted) : $decrypted;
    }

    public function decryptString(string $payload): string
    {
        return $this->decrypt($payload, false);
    }

    private function hash(string $iv, string $value, string $key): string
    {
        return hash_hmac('sha256', $iv . $value, $key);
    }

    private function getJsonPayload(string $payload): array
    {
        $decoded = json_decode(base64_decode($payload), true);

        if (!$this->validPayload($decoded)) {
            throw new DecryptException('The payload is invalid.');
        }

        return $decoded;
    }

    private function validPayload(mixed $payload): bool
    {
        if (!is_array($payload)) {
            return false;
        }

        foreach (['iv', 'value', 'mac'] as $item) {
            if (!isset($payload[$item]) || !is_string($payload[$item])) {
                return false;
            }
        }

        if (isset($payload['tag']) && !is_string($payload['tag'])) {
            return false;
        }

        return strlen(base64_decode($payload['iv'], true)) === openssl_cipher_iv_length($this->cipher);
    }

    private function validMacForKey(array $payload, string $key): bool
    {
        return hash_equals(
            $this->hash($payload['iv'], $payload['value'], $key),
            $payload['mac']
        );
    }

    private function ensureTagIsValid(?string $tag): void
    {
        $isAead = $this->isAead();

        if ($isAead && strlen($tag ?? '') !== 16) {
            throw new DecryptException('Could not decrypt the data.');
        }

        if (!$isAead && is_string($tag)) {
            throw new DecryptException('Unable to use tag because the cipher algorithm does not support AEAD.');
        }
    }

    private function isAead(): bool
    {
        return self::SUPPORTED_CIPHERS[$this->cipher]['aead'];
    }

    private function shouldValidateMac(): bool
    {
        return !$this->isAead();
    }

    public static function appearsEncrypted(mixed $value): bool
    {
        if (!is_string($value)) {
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

    /** @return string[] */
    public function getAllKeys(): array
    {
        return [$this->key, ...$this->previousKeys];
    }

    /** @return string[] */
    public function getPreviousKeys(): array
    {
        return $this->previousKeys;
    }

    public function previousKeys(array $keys): self
    {
        foreach ($keys as $key) {
            if (!self::supported($key, $this->cipher)) {
                $supported = implode(', ', array_keys(self::SUPPORTED_CIPHERS));
                throw new RuntimeException("Unsupported cipher or incorrect key length. Supported ciphers are: {$supported}.");
            }
        }

        $this->previousKeys = $keys;

        return $this;
    }
}
