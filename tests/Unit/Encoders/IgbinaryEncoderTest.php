<?php

declare(strict_types=1);

use CodeLieutenant\LaravelCrypto\Encoder\IgbinaryEncoder;

test('encode', function (): void {
    $encoder = new IgbinaryEncoder;

    $data = ['name' => 'John Doe', 'age' => 25];

    $encoded = $encoder->encode($data);

    expect($encoded)->toBe(igbinary_serialize($data));
});

test('decode', function (): void {
    $encoder = new IgbinaryEncoder;

    $data = igbinary_serialize(['name' => 'John Doe', 'age' => 25]);

    $decoded = $encoder->decode($data);

    expect($decoded)->toBe(['name' => 'John Doe', 'age' => 25]);
});
