<?php

declare(strict_types=1);

use CodeLieutenant\LaravelCrypto\Traits\LaravelKeyParser;
use Illuminate\Encryption\MissingAppKeyException;

$class = new class {
    use LaravelKeyParser {
        parseKey as public;
        parseKeys as public;
    }
};

test('parseKey with null or empty', function () use ($class) {
    expect(fn() => $class->parseKey(null))->toThrow(MissingAppKeyException::class)
        ->and(fn() => $class->parseKey(''))->toThrow(MissingAppKeyException::class)
        ->and($class->parseKey(null, true))->toBe('')
        ->and($class->parseKey('', true))->toBe('');
});

test('parseKey with base64', function () use ($class) {
    $data = 'test-key';
    $key = 'base64:'.base64_encode($data);
    expect($class->parseKey($key))->toBe($data);
});

test('parseKey with hex', function () use ($class) {
    $data = 'test-key';
    $key = bin2hex($data);
    expect($class->parseKey($key))->toBe($data);
});

test('parseKey with invalid hex', function () use ($class) {
    // hex2bin returns false and triggers a warning/error if length is odd.
    // parseKey uses hex2bin then throw_if false.
    // 'abc' has odd length, hex2bin('abc') returns false.
    expect(fn() => @$class->parseKey('abc'))->toThrow(RuntimeException::class, 'Application encryption key is not a valid hex string.');
});

test('parseKeys', function () use ($class) {
    $key1 = 'base64:'.base64_encode('key1');
    $key2 = bin2hex('key2');
    
    expect($class->parseKeys(null))->toBe([])
        ->and($class->parseKeys(''))->toBe([])
        ->and($class->parseKeys([$key1, $key2]))->toBe(['key1', 'key2'])
        ->and($class->parseKeys("$key1,$key2"))->toBe(['key1', 'key2']);
});
