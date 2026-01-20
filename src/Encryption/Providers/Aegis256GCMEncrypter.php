<?php

declare(strict_types=1);

namespace CodeLieutenant\LaravelCrypto\Encryption\Providers;

use CodeLieutenant\LaravelCrypto\Contracts\EncrypterProvider;
use Illuminate\Contracts\Encryption\DecryptException;
use SensitiveParameter;

final readonly class Aegis256GCMEncrypter implements EncrypterProvider
{
    public function nonceSize(): int
    {
        return defined('SODIUM_CRYPTO_AEAD_AEGIS256_NPUBBYTES') ? SODIUM_CRYPTO_AEAD_AEGIS256_NPUBBYTES : 32;
    }

    public function encrypt(#[SensitiveParameter] string $key, #[SensitiveParameter] mixed $value, string $nonce): string
    {
        return sodium_crypto_aead_aegis256_encrypt($value, '', $nonce, $key);
    }

    public function decrypt(#[SensitiveParameter] string $key, string $payload, string $nonce): mixed
    {
        $decrypted = sodium_crypto_aead_aegis256_decrypt($payload, '', $nonce, $key);

        throw_if($decrypted === false, DecryptException::class, 'Payload cannot be decrypted');

        return $decrypted;
    }
}
