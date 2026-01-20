<?php

declare(strict_types=1);

use CodeLieutenant\LaravelCrypto\Encoder\PhpEncoder;

test('encode', function (): void {
    $encoder = new PhpEncoder;

    $data = ['name' => 'John Doe', 'age' => 25];

    $encoded = $encoder->encode($data);

    expect($encoded)->toBe('a:2:{s:4:"name";s:8:"John Doe";s:3:"age";i:25;}');
});

test('decode', function (): void {
    $encoder = new PhpEncoder;

    $data = 'a:2:{s:4:"name";s:8:"John Doe";s:3:"age";i:25;}';

    $decoded = $encoder->decode($data);

    expect($decoded)->toBe(['name' => 'John Doe', 'age' => 25]);
});

test('decode as object', function (): void {
    $encoder = new PhpEncoder;

    $data = 'O:8:"stdClass":2:{s:4:"name";s:8:"John Doe";s:3:"age";i:25;}';

    $decoded = $encoder->decode($data);

    $class = new stdClass;
    $class->name = 'John Doe';
    $class->age = 25;

    expect($decoded)->toBeObject()
        ->toEqual($class);
});
