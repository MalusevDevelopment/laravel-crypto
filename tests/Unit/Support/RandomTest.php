<?php

declare(strict_types=1);

use CodeLieutenant\LaravelCrypto\Support\Random;
use Random\Engine\Secure;
use Random\Randomizer;

beforeEach(function () {
    $this->random = new Random(new Randomizer(new Secure));
});

test('bytes', function () {
    $bytes = $this->random->bytes(16);
    expect(strlen($bytes))->toBe(16);
});

test('string', function () {
    $string = $this->random->string(16);
    expect($string)->toBeString();
    // Base64UrlEncoded 16 bytes might be different length than 16 characters
    // Random::string(16) actually calls getBytes(Base64::encodedLength(16))
    // which is 22 for 16 bytes (no padding)
    // and then encodes it.
});

test('int', function () {
    $int = $this->random->int(1, 10);
    expect($int)->toBeBetween(1, 10);
});
