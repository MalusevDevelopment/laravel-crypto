<?php

declare(strict_types=1);

namespace CodeLieutenant\LaravelCrypto\Benchmarks;

use CodeLieutenant\LaravelCrypto\Contracts\KeyLoader;

class KeyKeyLoader implements KeyLoader
{
    public function __construct(
        private readonly string $key
    ) {}

    public function getKey(): string|array
    {
        return $this->key;
    }
}
