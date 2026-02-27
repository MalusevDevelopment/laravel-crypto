<?php

declare(strict_types=1);

namespace CodeLieutenant\LaravelCrypto\Encryption\Providers;

use CodeLieutenant\LaravelCrypto\Contracts\EncrypterProvider;
use CodeLieutenant\LaravelCrypto\Traits\StreamEncryptionTrait;
use Illuminate\Contracts\Encryption\DecryptException;
use SensitiveParameter;

final readonly class Aegis128LGCMEncrypter implements EncrypterProvider
{
    use StreamEncryptionTrait;

    public function nonceSize(): int
    {
        return defined('SODIUM_CRYPTO_AEAD_AEGIS128L_NPUBBYTES') ? SODIUM_CRYPTO_AEAD_AEGIS128L_NPUBBYTES : 16;
    }

    public function tagSize(): int
    {
        return defined('SODIUM_CRYPTO_AEAD_AEGIS128L_ABYTES') ? SODIUM_CRYPTO_AEAD_AEGIS128L_ABYTES : 32;
    }

    public function encrypt(#[SensitiveParameter] string $key, #[SensitiveParameter] mixed $value, string $nonce): string
    {
        return sodium_crypto_aead_aegis128l_encrypt($value, $nonce, $nonce, $key);
    }

    public function decrypt(#[SensitiveParameter] string $key, string $payload, string $nonce): mixed
    {
        $decrypted = sodium_crypto_aead_aegis128l_decrypt($payload, $nonce, $nonce, $key);

        throw_if($decrypted === false, DecryptException::class, 'Payload cannot be decrypted');

        return $decrypted;
    }

    public function encryptChunk(#[SensitiveParameter] string $key, string $chunk, string $nonce): string
    {
        return sodium_crypto_aead_aegis128l_encrypt($chunk, $nonce, $nonce, $key);
    }

    public function decryptChunk(#[SensitiveParameter] string $key, string $chunk, string $nonce): string
    {
        $decrypted = sodium_crypto_aead_aegis128l_decrypt($chunk, $nonce, $nonce, $key);

        if ($decrypted === false) {
            throw new DecryptException('Payload cannot be decrypted');
        }

        return $decrypted;
    }
}
