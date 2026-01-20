<?php

declare(strict_types=1);

use CodeLieutenant\LaravelCrypto\Enums\Encryption;
use CodeLieutenant\LaravelCrypto\Traits\Crypto;

class TestTraitImpl
{
    use Crypto;

    public static function nonceSize(): int
    {
        return 16;
    }
}

test('generate nonce -> without previous', function (): void {
    $testCrypto = new TestTraitImpl;
    $nonce = $testCrypto->generateNonce();
    $nonce2 = $testCrypto->generateNonce();

    expect($nonce)->toBeString()
        ->and(strlen($nonce))
        ->toBe(16)
        ->and($nonce2)
        ->toBeString()
        ->and(strlen($nonce2))
        ->toBe(16)
        ->and($nonce)->not->toBe($nonce2);
});

test('generate nonce -> with previous', function (): void {
    $testCrypto = new TestTraitImpl;
    $nonce = $testCrypto->generateNonce();
    $nonce2 = $testCrypto->generateNonce($nonce);

    expect($nonce)->toBeString()
        ->and(strlen($nonce))
        ->toBe(16)
        ->and($nonce2)
        ->toBeString()
        ->and(strlen($nonce2))
        ->toBe(16)
        ->and(ord($nonce[0]) + 1)->toBe(ord($nonce2[0]))
        ->and(substr($nonce, 1))->toBe(substr($nonce2, 1));
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
