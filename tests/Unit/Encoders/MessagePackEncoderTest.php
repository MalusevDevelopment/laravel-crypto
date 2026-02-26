<?php

declare(strict_types=1);

use CodeLieutenant\LaravelCrypto\Encoder\MessagePackEncoder;

beforeEach(function (): void {
    if (!extension_loaded('msgpack')) {
        $this->markTestSkipped('msgpack extension is not loaded');
    }
});

test('encode', function (): void {
    $encoder = new MessagePackEncoder;

    $data = ['name' => 'John Doe', 'age' => 25];

    $encoded = $encoder->encode($data);

    expect($encoded)->toBe(msgpack_serialize($data));
});

test('decode', function (): void {
    $encoder = new MessagePackEncoder;

    $data = msgpack_serialize(['name' => 'John Doe', 'age' => 25]);

    $decoded = $encoder->decode($data);

    expect($decoded)->toBe(['name' => 'John Doe', 'age' => 25]);
});
