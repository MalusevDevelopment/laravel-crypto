<?php

declare(strict_types=1);

use CodeLieutenant\LaravelCrypto\Hashing\Sha512;

function hash512(string $value): string
{
    return hash('sha512', $value, true);
}

function hash512Encoded(string $value): string
{
    return hash('sha512', $value);
}

test('hashing', function (): void {
    $hasher = new Sha512;
    expect($hasher->hash('hello world'))->toBe(hash512Encoded('hello world'));
});

test('hashing raw', function (): void {
    $hasher = new Sha512;
    expect($hasher->hashRaw('hello world'))->toBe(
        hash512('hello world'),
    );
});

test('hashing verify', function (): void {
    $hasher = new Sha512;

    $data = 'hello world';
    $hash = hash512Encoded($data);

    expect($hasher->verify($hash, $data))
        ->toBeTrue()
        ->and($hasher->verify($hash, 'wrong input'))
        ->toBeFalse();
});

test('hashing raw verify', function (): void {
    $hasher = new Sha512;

    $data = 'hello world';
    $hash = hash512($data);

    expect($hasher->verifyRaw($hash, $data))
        ->toBeTrue()
        ->and($hasher->verifyRaw($hash, 'wrong input'))
        ->toBeFalse();
});
