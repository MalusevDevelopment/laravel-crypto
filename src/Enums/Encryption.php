<?php

declare(strict_types=1);

namespace CodeLieutenant\LaravelCrypto\Enums;

enum Encryption: string
{
    case SodiumAES256GCM = 'Sodium_AES256GCM';
    case SodiumXChaCha20Poly1305 = 'Sodium_XChaCha20Poly1305';
    case SodiumAEGIS256GCM = 'Sodium_AEGIS256GCM';
    case SodiumAEGIS128LGCM = 'Sodium_AEGIS128LGCM';

    public function keySize(): int
    {
        return match ($this) {
            self::SodiumAES256GCM => SODIUM_CRYPTO_AEAD_AES256GCM_KEYBYTES,
            self::SodiumAEGIS256GCM => SODIUM_CRYPTO_AEAD_AEGIS256_KEYBYTES,
            self::SodiumAEGIS128LGCM => SODIUM_CRYPTO_AEAD_AEGIS128L_KEYBYTES,
            self::SodiumXChaCha20Poly1305 => SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_KEYBYTES,
        };
    }
}
