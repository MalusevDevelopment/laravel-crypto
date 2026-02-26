<?php

declare(strict_types=1);

namespace CodeLieutenant\LaravelCrypto\Encryption\Providers;

use CodeLieutenant\LaravelCrypto\Contracts\EncrypterProvider;
use CodeLieutenant\LaravelCrypto\Traits\StreamEncryptionTrait;
use Illuminate\Contracts\Encryption\DecryptException;
use SensitiveParameter;

final readonly class XChaCha20Poly1305Encrypter implements EncrypterProvider
{
    use StreamEncryptionTrait;

    public function nonceSize(): int
    {
        return SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES;
    }

    public function tagSize(): int
    {
        return SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_ABYTES;
    }

    public function encrypt(#[SensitiveParameter] string $key, #[SensitiveParameter] mixed $value, string $nonce): string
    {
        return sodium_crypto_aead_xchacha20poly1305_ietf_encrypt((string) $value, '', $nonce, $key);
    }

    public function decrypt(#[SensitiveParameter] string $key, string $payload, string $nonce): mixed
    {
        $value = sodium_crypto_aead_xchacha20poly1305_ietf_decrypt($payload, '', $nonce, $key);

        throw_if($value === false, DecryptException::class, 'Payload cannot be decrypted');

        return $value;
    }

    public function encryptChunk(#[SensitiveParameter] string $key, string $chunk, string $nonce): string
    {
        return sodium_crypto_aead_xchacha20poly1305_ietf_encrypt($chunk, '', $nonce, $key);
    }

    public function decryptChunk(#[SensitiveParameter] string $key, string $chunk, string $nonce): string
    {
        $decrypted = sodium_crypto_aead_xchacha20poly1305_ietf_decrypt($chunk, '', $nonce, $key);

        if ($decrypted === false) {
            throw new DecryptException('Payload cannot be decrypted');
        }

        return $decrypted;
    }
}
