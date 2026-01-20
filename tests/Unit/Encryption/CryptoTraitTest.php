<?php

declare(strict_types=1);

use CodeLieutenant\LaravelCrypto\Contracts\EncrypterProvider;
use CodeLieutenant\LaravelCrypto\Encoder\JsonEncoder;
use CodeLieutenant\LaravelCrypto\Encryption\Encrypter;
use CodeLieutenant\LaravelCrypto\Enums\Encryption;
use CodeLieutenant\LaravelCrypto\Traits\Crypto;
use Illuminate\Contracts\Encryption\DecryptException;
use Illuminate\Contracts\Encryption\EncryptException;

class TestTraitImpl implements EncrypterProvider
{
    public function nonceSize(): int
    {
        return 24;
    }

    public function encrypt(#[SensitiveParameter] string $key, #[SensitiveParameter] mixed $value, string $nonce): string
    {
        try {
            return sodium_crypto_aead_xchacha20poly1305_ietf_encrypt((string) $value, $nonce, $nonce, $key);
        } catch (Error|Exception $e) {
            throw new EncryptException('Value cannot be encrypted '.$e->getMessage(), previous: $e);
        }
    }

    public function decrypt(#[SensitiveParameter] string $key, string $payload, string $nonce): mixed
    {
        try {
            $value = sodium_crypto_aead_xchacha20poly1305_ietf_decrypt($payload, $nonce, $nonce, $key);

            throw_if($value === false, DecryptException::class, 'Payload cannot be decrypted');

            return $value;
        } catch (Error|Exception $e) {
            throw new DecryptException('Payload cannot be decrypted '.$e->getMessage(), previous: $e);
        }
    }

    public static function supported(string $key, string $cipher): bool
    {
        return Crypto::supported($key, $cipher);
    }
}

test('generate nonce -> without previous', function (): void {
    $encrypter = new Encrypter(inMemoryKeyLoader(), new JsonEncoder, null, new TestTraitImpl);
    $nonce = $encrypter->generateNonce();
    $nonce2 = $encrypter->generateNonce();

    expect($nonce)->toBeString()
        ->and(strlen($nonce))
        ->toBe(24)
        ->and($nonce2)
        ->toBeString()
        ->and(strlen($nonce2))
        ->toBe(24)
        ->and($nonce)->not->toBe($nonce2);
});

test('generate nonce -> with previous', function (): void {
    $encrypter = new Encrypter(inMemoryKeyLoader(), new JsonEncoder, null, new TestTraitImpl);
    $nonce = $encrypter->generateNonce();
    $nonce2 = $encrypter->generateNonce($nonce);

    expect($nonce)->toBeString()
        ->and(strlen($nonce))
        ->toBe(24)
        ->and($nonce2)
        ->toBeString()
        ->and(strlen($nonce2))
        ->toBe(24)
        ->and(ord($nonce[0]) + 1)->toBe(ord($nonce2[0]))
        ->and(substr($nonce, 1))->toBe(substr($nonce2, 1));
});

test('encrypt/decrypt using custom provider', function (): void {
    $encrypter = new Encrypter(inMemoryKeyLoader(32), new JsonEncoder, null, new TestTraitImpl);

    $data = 'hello world';
    $encrypted = $encrypter->encryptString($data);

    expect($encrypted)->toBeString()
        ->and($encrypter->decryptString($encrypted))->toBe($data);
});

test('supported algorithms', function (int $keyLength, string $cipher): void {
    $key = random_bytes($keyLength);
    expect(TestTraitImpl::supported($key, $cipher))->toBetrue();
})->with([
    [Encryption::SodiumAES256GCM->keySize(), Encryption::SodiumAES256GCM->value],
    [Encryption::SodiumXChaCha20Poly1305->keySize(), Encryption::SodiumXChaCha20Poly1305->value],
    [32, 'AES-256-GCM'],
    [32, 'AES-256-CBC'],
    [16, 'AES-128-CBC'],
    [16, 'AES-128-GCM'],
]);

test('not supported algorithms', function (int $keyLength, string $cipher): void {
    $key = random_bytes($keyLength);
    expect(TestTraitImpl::supported($key, $cipher))->toBeFalse();
})->with([
    [16, 'invalid algorithm'],
    [32, 'AES-128-CBC'],
    [32, 'AES-128-GCM'],
    [16, 'AES-256-GCM'],
    [16, 'AES-256-CBC'],
]);
