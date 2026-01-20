<?php

declare(strict_types=1);

use CodeLieutenant\LaravelCrypto\Hashing\Blake2b;

function bcryptHash(string $value, string $key, int $outputLength = 32): string
{
    return sodium_crypto_generichash($value, $key, $outputLength);
}

function bcryptHashEncoded(string $value, string $key, int $outputLength = 32): string
{
    return str_replace(
        ['+', '/', '='],
        ['-', '_', ''],
        base64_encode(bcryptHash($value, $key, $outputLength)),
    );
}

test('hashing', function (): void {
    $outputLength = 32;
    $hasher = new Blake2b(outputLength: $outputLength);
    expect($hasher->hash('hello world'))->toBe(bcryptHashEncoded('hello world', '', $outputLength));
});

test('hashing raw', function (): void {
    $outputLength = 32;
    $hasher = new Blake2b(outputLength: $outputLength);
    expect($hasher->hashRaw('hello world'))->toBe(
        bcryptHash('hello world', '', $outputLength),
    );
});

test('hashing with key', function (): void {
    $key = random_bytes(32);
    $outputLength = 32;
    $hasher = new Blake2b($key, $outputLength);

    expect($hasher->hash('hello world'))->toBe(bcryptHashEncoded('hello world', $key, $outputLength));
});

test('hashing raw with key', function (): void {
    $key = random_bytes(32);
    $outputLength = 32;
    $hasher = new Blake2b($key, $outputLength);

    expect($hasher->hashRaw('hello world'))->toBe(bcryptHash('hello world', $key, $outputLength));
});

test('hashing verify', function (): void {
    $outputLength = 32;
    $hasher = new Blake2b(outputLength: $outputLength);

    $data = 'hello world';
    $hash = bcryptHashEncoded($data, '', $outputLength);

    expect($hasher->verify($hash, $data))
        ->toBeTrue()
        ->and($hasher->verify($hash, 'wrong input'))
        ->toBeFalse();
});

test('hashing raw verify', function (): void {
    $outputLength = 32;
    $hasher = new Blake2b(outputLength: $outputLength);

    $data = 'hello world';
    $hash = bcryptHash($data, '', $outputLength);

    expect($hasher->verifyRaw($hash, $data))
        ->toBeTrue()
        ->and($hasher->verifyRaw($hash, 'wrong input'))
        ->toBeFalse();
});
