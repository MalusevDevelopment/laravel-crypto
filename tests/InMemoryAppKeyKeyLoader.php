<?php

declare(strict_types=1);

namespace CodeLieutenant\LaravelCrypto\Tests;

use CodeLieutenant\LaravelCrypto\Contracts\KeyLoader;
use Illuminate\Support\Str;

class InMemoryAppKeyKeyLoader implements KeyLoader
{
    public function __construct(private readonly string $key) {}

    public function getKey(): string|array
    {
        return Str::of($this->key)
            ->remove('base64:', $this->key)
            ->fromBase64()
            ->toString();
    }
}
