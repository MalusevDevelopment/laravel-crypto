<?php

declare(strict_types=1);

namespace CodeLieutenant\LaravelCrypto\Enums;

enum Encryption: string
{
    case AES256GCM = 'AES-256-GCM';
    case AES256CBC = 'AES-256-CBC';
    case SodiumAES256GCM = 'Sodium_AES256GCM';
    case SodiumXChaCha20Poly1305 = 'Sodium_XChaCha20Poly1305';

    public function keySize(): int
    {
        return match ($this) {
            self::SodiumAES256GCM => SODIUM_CRYPTO_AEAD_AES256GCM_KEYBYTES,
            self::SodiumXChaCha20Poly1305 => SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_KEYBYTES,
            self::AES256GCM, self::AES256CBC => 32,
        };
    }
}
