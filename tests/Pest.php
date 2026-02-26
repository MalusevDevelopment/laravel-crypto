<?php

declare(strict_types=1);

use CodeLieutenant\LaravelCrypto\Contracts\KeyLoader;
use CodeLieutenant\LaravelCrypto\Tests\InMemoryAppKeyKeyLoader;
use CodeLieutenant\LaravelCrypto\Tests\TestCase;

uses(TestCase::class)->in(__DIR__);

function inMemoryKeyLoader(?int $length = null, array $previousKeys = []): KeyLoader
{
    if ($length !== null) {
        return new InMemoryAppKeyKeyLoader(base64_encode(random_bytes($length)), $previousKeys);
    }

    $key = config('app.key', 'base64:'.base64_encode(random_bytes(32)));

    return new InMemoryAppKeyKeyLoader($key, $previousKeys);
}

expect()->extend('toBeBase64', function () {
    if (! preg_match('/^[-A-Za-z0-9+\/]+={0,3}$/', preg_quote((string) $this->value, '/'))) {
        throw new RuntimeException(sprintf('Value %s is not a valid base64 string', $this->value));
    }

    return $this;
});

expect()->extend('toBeBase64NoPadding', function () {
    if (! preg_match('/^[-A-Za-z0-9+\/]+$/', preg_quote((string) $this->value, '/'))) {
        throw new RuntimeException(sprintf('Value %s is not a valid base64 string', $this->value));
    }

    return $this;
});

expect()->extend('toBeBase64Url', function () {
    if (! preg_match('/^[-A-Za-z0-9_-]+={0,3}$/', (string) $this->value)) {
        throw new RuntimeException(sprintf('Value %s is not a valid base64 string', $this->value));
    }

    return $this;
});

expect()->extend('toBeBase64UrlNoPadding', function () {
    if (! preg_match('/^[-A-Za-z0-9_-]+$/', (string) $this->value)) {
        throw new RuntimeException(sprintf('Value %s is not a valid base64 string', $this->value));
    }

    return $this;
});
