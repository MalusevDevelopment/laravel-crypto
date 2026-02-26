<?php

declare(strict_types=1);

use CodeLieutenant\LaravelCrypto\Facades\Hashing;
use CodeLieutenant\LaravelCrypto\Facades\Random;
use CodeLieutenant\LaravelCrypto\Facades\Sign;
use CodeLieutenant\LaravelCrypto\Signing\Hmac\Blake2b as HmacBlake2b;
use Illuminate\Support\Facades\Config;

test('hashing facade', function (): void {
    $data = 'test data';
    $hash = Hashing::blake2b($data);
    expect(Hashing::blake2bVerify($hash, $data))->toBeTrue();
});

test('random facade', function (): void {
    $bytes = Random::bytes(16);
    expect(strlen($bytes))->toBe(16)
        ->and(Random::string(16))->toBeString()
        ->and(Random::int(1, 10))->toBeBetween(1, 10);
});

test('sign facade', function (): void {
    Config::set('crypto.signing.keys.hmac', 'base64:'.base64_encode(str_repeat('k', 32)));
    Config::set('crypto.signing.config.'.HmacBlake2b::class, 32);

    $data = 'test data';
    $sig = Sign::blake2bSign($data);
    expect(Sign::blake2bVerify($data, $sig))->toBeTrue();
});
