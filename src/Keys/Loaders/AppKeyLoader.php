<?php

declare(strict_types=1);

namespace CodeLieutenant\LaravelCrypto\Keys\Loaders;

use CodeLieutenant\LaravelCrypto\Contracts\KeyLoader;
use CodeLieutenant\LaravelCrypto\Traits\LaravelKeyParser;
use Illuminate\Contracts\Config\Repository;

class AppKeyLoader implements KeyLoader
{
    use LaravelKeyParser;

    public const CONFIG_KEY_PATH = 'app.key';

    public const string CONFIG_PREVIOUS_KEYS_PATH = 'app.previous_keys';

    public function __construct(
        protected readonly string $key,
        protected readonly array $previousKeys = []
    ) {}

    public static function make(Repository $config): static
    {
        return new static(
            self::parseKey($config->get(static::CONFIG_KEY_PATH)),
            self::parseKeys($config->get(static::CONFIG_PREVIOUS_KEYS_PATH))
        );
    }

    public function getKey(): string|array
    {
        return $this->key;
    }

    public function getPreviousKeys(): array
    {
        return $this->previousKeys;
    }
}
