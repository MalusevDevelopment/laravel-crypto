<?php

declare(strict_types=1);

namespace CodeLieutenant\LaravelCrypto\Facades;

use CodeLieutenant\LaravelCrypto\Support\Random as RandomManager;
use Illuminate\Support\Facades\Facade;

/**
 * Class Hashing
 *
 *
 * @method static string bytes(int $length)
 * @method static string string(int $length)
 * @method static int int(int $min = PHP_INT_MIN, int $max = PHP_INT_MAX)
 */
class Random extends Facade
{
    protected static function getFacadeAccessor(): string
    {
        return RandomManager::class;
    }
}
