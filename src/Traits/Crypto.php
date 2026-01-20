<?php

declare(strict_types=1);

namespace CodeLieutenant\LaravelCrypto\Traits;

use CodeLieutenant\LaravelCrypto\Enums\Encryption;
use CodeLieutenant\LaravelCrypto\Facades\Random;
use Illuminate\Encryption\Encrypter as LaravelEncrypter;

trait Crypto
{
    abstract public static function nonceSize(): int;

    public function getKey(): string
    {
        return $this->keyLoader->getKey();
    }

    public function getAllKeys(): array
    {
        return [$this->getKey(), ...$this->getPreviousKeys()];
    }

    /**
     * @return array{}
     */
    public function getPreviousKeys(): array
    {
        return [];
    }

    public static function supported(string $key, string $cipher): bool
    {
        return match ($encType = Encryption::tryFrom($cipher)) {
            null => LaravelEncrypter::supported($key, $cipher),
            Encryption::SodiumAES256GCM => sodium_crypto_aead_aes256gcm_is_available(),
            default => strlen($key) === $encType->keySize()
        };
    }

    public function encryptString($value): string
    {
        return $this->encrypt($value, false);
    }

    public function decryptString($payload): string
    {
        return $this->decrypt($payload, false);
    }

    public function generateNonce(?string $previous = null): string
    {
        if ($previous !== null) {
            $copy = $previous;
            sodium_increment($copy);

            return $copy;
        }

        return Random::bytes(static::nonceSize());
    }
}
