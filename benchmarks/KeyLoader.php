<?php

declare(strict_types=1);

namespace CodeLieutenant\LaravelCrypto\Benchmarks;

use CodeLieutenant\LaravelCrypto\Contracts\KeyLoader as KeyLoaderContract;

final readonly class KeyLoader implements KeyLoaderContract
{
    public function __construct(private string $key) {}

    public function getKey(): string|array
    {
        return $this->key;
    }
}
