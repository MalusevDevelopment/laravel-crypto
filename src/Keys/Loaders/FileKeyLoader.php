<?php

declare(strict_types=1);

namespace CodeLieutenant\LaravelCrypto\Keys\Loaders;

use CodeLieutenant\LaravelCrypto\Contracts\KeyLoader;
use CodeLieutenant\LaravelCrypto\Traits\LaravelKeyParser;
use Illuminate\Contracts\Config\Repository;

class FileKeyLoader implements KeyLoader
{
    use LaravelKeyParser;

    public function __construct(
        protected readonly string $key,
        protected readonly array $previousKeys = []
    ) {}

    public static function make(Repository $config): static
    {
        $key = $config->get('crypto.file_encryption.key');
        $previousKeys = $config->get('crypto.file_encryption.previous_keys');

        if ($key === null || $key === '') {
            $key = $config->get(AppKeyLoader::CONFIG_KEY_PATH);
        }

        if ($previousKeys === null || $previousKeys === '') {
            $previousKeys = $config->get(AppKeyLoader::CONFIG_PREVIOUS_KEYS_PATH);
        }

        return new static(
            self::parseKey($key),
            self::parseKeys($previousKeys)
        );
    }

    public function getKey(): string
    {
        return $this->key;
    }

    public function getPreviousKeys(): array
    {
        return $this->previousKeys;
    }
}
