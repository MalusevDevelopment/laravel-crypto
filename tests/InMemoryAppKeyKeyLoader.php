<?php

declare(strict_types=1);

namespace CodeLieutenant\LaravelCrypto\Tests;

use CodeLieutenant\LaravelCrypto\Contracts\KeyLoader;
use Illuminate\Support\Str;

class InMemoryAppKeyKeyLoader implements KeyLoader
{
    /**
     * @param  string[]  $previousKeys
     */
    public function __construct(private readonly string $key, private readonly array $previousKeys = []) {}

    public function getKey(): string|array
    {
        return $this->parse($this->key);
    }

    public function getPreviousKeys(): array
    {
        return array_map($this->parse(...), $this->previousKeys);
    }

    private function parse(string $key): string
    {
        return Str::of($key)
            ->remove('base64:', $key)
            ->fromBase64()
            ->toString();
    }
}
