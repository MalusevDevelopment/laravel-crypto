<?php

declare(strict_types=1);

use CodeLieutenant\LaravelCrypto\Hashing\Sha256;

function hash256(string $value): string
{
    return hash('sha512/256', $value, true);
}

function hash256Encoded(string $value): string
{
    return hash('sha512/256', $value);
}

test('hashing', function (): void {
    $hasher = new Sha256;
    expect($hasher->hash('hello world'))->toBe(hash256Encoded('hello world'));
});

test('hashing raw', function (): void {
    $hasher = new Sha256;
    expect($hasher->hashRaw('hello world'))->toBe(
        hash256('hello world'),
    );
});

test('hashing verify', function (): void {
    $hasher = new Sha256;

    $data = 'hello world';
    $hash = hash256Encoded($data);

    expect($hasher->verify($hash, $data))
        ->toBeTrue()
        ->and($hasher->verify($hash, 'wrong input'))
        ->toBeFalse();
});

test('hashing raw verify', function (): void {
    $hasher = new Sha256;

    $data = 'hello world';
    $hash = hash256($data);

    expect($hasher->verifyRaw($hash, $data))
        ->toBeTrue()
        ->and($hasher->verifyRaw($hash, 'wrong input'))
        ->toBeFalse();
});
