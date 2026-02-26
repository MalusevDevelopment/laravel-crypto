<?php

declare(strict_types=1);

namespace CodeLieutenant\LaravelCrypto\Encryption\Providers;

use CodeLieutenant\LaravelCrypto\Contracts\EncrypterProvider;
use CodeLieutenant\LaravelCrypto\Support\Random;
use CodeLieutenant\LaravelCrypto\Traits\StreamEncryptionTrait;
use Illuminate\Contracts\Encryption\DecryptException;
use Illuminate\Contracts\Encryption\EncryptException;
use Illuminate\Encryption\Encrypter as LaravelEncrypter;
use SensitiveParameter;
use Throwable;

final class OpenSSLEncrypter implements EncrypterProvider
{
    use StreamEncryptionTrait;

    private static int $memoryLimitBytes;
    private LaravelEncrypter $laravel;
    private readonly bool $isGcm;

    public function __construct(
        private readonly Random $random,
        private readonly string $cipher,
    ) {
        $this->isGcm = str_contains(strtolower($this->cipher), 'gcm');
    }

    public function nonceSize(): int
    {
        return openssl_cipher_iv_length($this->cipher);
    }

    public function tagSize(): int
    {
        // GCM: 16 bytes tag.
        // CBC: 16 bytes MAC + 16 bytes padding = 32 bytes.
        return $this->isGcm ? 16 : 32;
    }

    public function encrypt(#[SensitiveParameter] string $key, #[SensitiveParameter] mixed $value, string $nonce): string
    {
        try {
            return $this->laravel($key)->encrypt($value, serialize: false);
        } catch (Throwable $e) {
            throw new EncryptException('Could not encrypt the data.', previous: $e);
        }
    }

    public function decrypt(#[SensitiveParameter] string $key, string $payload, string $nonce): mixed
    {
        try {
            return $this->laravel($key)->decrypt($payload, unserialize: false);
        } catch (Throwable $e) {
            throw new DecryptException('Could not decrypt the data.', previous: $e);
        }
    }

    public function encryptChunk(#[SensitiveParameter] string $key, string $chunk, string $nonce): string
    {
        if ($this->isGcm) {
            $tag = '';
            $encrypted = openssl_encrypt($chunk, $this->cipher, $key, OPENSSL_RAW_DATA, $nonce, $tag);
            if ($encrypted === false) {
                throw new EncryptException('Encryption failed');
            }

            return $tag.$encrypted;
        }

        $encrypted = openssl_encrypt($chunk, $this->cipher, $key, OPENSSL_RAW_DATA, $nonce);
        if ($encrypted === false) {
            throw new EncryptException('Encryption failed');
        }

        $mac = substr(hash_hmac(EncrypterProvider::HMAC_ALGORITHM, $encrypted, $key, true), 0, 16);

        return $mac.$encrypted;
    }

    public function decryptChunk(#[SensitiveParameter] string $key, string $chunk, string $nonce): string
    {
        if ($this->isGcm) {
            $tag = substr($chunk, 0, 16);
            $ciphertext = substr($chunk, 16);

            $decrypted = openssl_decrypt($ciphertext, $this->cipher, $key, OPENSSL_RAW_DATA, $nonce, $tag);
            if ($decrypted === false) {
                throw new DecryptException('Payload cannot be decrypted');
            }

            return $decrypted;
        }

        $mac = substr($chunk, 0, 16);
        $ciphertext = substr($chunk, 16);

        if (!hash_equals($mac, substr(hash_hmac(EncrypterProvider::HMAC_ALGORITHM, $ciphertext, $key, true), 0, 16))) {
            throw new DecryptException('Chunk integrity check failed');
        }

        $decrypted = openssl_decrypt($ciphertext, $this->cipher, $key, OPENSSL_RAW_DATA, $nonce);
        if ($decrypted === false) {
            throw new DecryptException('Payload cannot be decrypted');
        }

        return $decrypted;
    }

    private function laravel(string $key): LaravelEncrypter
    {
        if (!isset($this->laravel)) {
            $this->laravel = new LaravelEncrypter($key, strtolower($this->cipher));
        }

        return $this->laravel;
    }

    private static function getMemoryLimit(): int
    {
        if (isset(self::$memoryLimitBytes)) {
            return self::$memoryLimitBytes;
        }

        $limit = ini_get('memory_limit');
        if (!$limit || $limit === '-1') {
            return self::$memoryLimitBytes = PHP_INT_MAX;
        }

        $unit = strtolower(substr($limit, -1));
        $value = (int)$limit;

        $value *= match ($unit) {
            'g' => 1024 * 1024 * 1024,
            'm' => 1024 * 1024,
            'k' => 1024,
            default => 1,
        };

        return self::$memoryLimitBytes = $value;
    }
}
