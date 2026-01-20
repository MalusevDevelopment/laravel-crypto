<?php

declare(strict_types=1);

namespace CodeLieutenant\LaravelCrypto\Encryption\Providers;

use CodeLieutenant\LaravelCrypto\Contracts\EncrypterProvider;
use Illuminate\Contracts\Encryption\DecryptException;
use SensitiveParameter;

final readonly class AesGcm256Encrypter implements EncrypterProvider
{
    public function nonceSize(): int
    {
        return SODIUM_CRYPTO_AEAD_AES256GCM_NPUBBYTES;
    }

    public function encrypt(#[SensitiveParameter] string $key, #[SensitiveParameter] mixed $value, string $nonce): string
    {
        return sodium_crypto_aead_aes256gcm_encrypt((string) $value, '', $nonce, $key);
    }

    public function decrypt(#[SensitiveParameter] string $key, string $payload, string $nonce): mixed
    {
        $value = sodium_crypto_aead_aes256gcm_decrypt($payload, '', $nonce, $key);

        throw_if($value === false, DecryptException::class, 'Payload cannot be decrypted');

        return $value;
    }
}
