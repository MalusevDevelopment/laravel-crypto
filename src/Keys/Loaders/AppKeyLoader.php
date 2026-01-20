<?php

declare(strict_types=1);

namespace CodeLieutenant\LaravelCrypto\Keys\Loaders;

use CodeLieutenant\LaravelCrypto\Contracts\KeyLoader;
use CodeLieutenant\LaravelCrypto\Traits\LaravelKeyParser;
use Illuminate\Contracts\Config\Repository;

class AppKeyLoader implements KeyLoader
{
    use LaravelKeyParser;

    protected static string $key;

    public const CONFIG_KEY_PATH = 'app.key';

    public static function make(Repository $config): static
    {
        if (! isset(static::$key)) {
            static::$key = self::parseKey($config->get(static::CONFIG_KEY_PATH));
        }

        return new static;
    }

    public function getKey(): string|array
    {
        return self::$key;
    }
}
