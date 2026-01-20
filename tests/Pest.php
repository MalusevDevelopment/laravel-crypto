<?php

declare(strict_types=1);

use CodeLieutenant\LaravelCrypto\Contracts\KeyLoader;
use CodeLieutenant\LaravelCrypto\Tests\InMemoryAppKeyKeyLoader;
use CodeLieutenant\LaravelCrypto\Tests\TestCase;

uses(TestCase::class)->in(__DIR__);

function inMemoryKeyLoader(): KeyLoader
{
    return new InMemoryAppKeyKeyLoader(config('app.key'));
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
