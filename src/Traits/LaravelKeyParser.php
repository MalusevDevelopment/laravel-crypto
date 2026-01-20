<?php

declare(strict_types=1);

namespace CodeLieutenant\LaravelCrypto\Traits;

use CodeLieutenant\LaravelCrypto\Support\Base64;
use Illuminate\Encryption\MissingAppKeyException;
use RuntimeException;

trait LaravelKeyParser
{
    protected static function parseKey(?string $key, bool $allowEmpty = false): string
    {
        if ($key === null || $key === '') {
            throw_unless($allowEmpty, MissingAppKeyException::class);

            return '';
        }

        if (str_starts_with($key, $prefix = 'base64:')) {
            return Base64::decode(substr($key, strlen($prefix)));
        }

        $key = hex2bin($key);

        throw_if($key === false, RuntimeException::class, 'Application encryption key is not a valid hex string.');

        return $key;
    }
}
