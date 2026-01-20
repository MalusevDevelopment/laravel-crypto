<?php

declare(strict_types=1);

namespace CodeLieutenant\LaravelCrypto\Encoder;

use CodeLieutenant\LaravelCrypto\Contracts\Encoder;
use RuntimeException;

class IgbinaryEncoder implements Encoder
{
    public function __construct()
    {
        throw_unless(extension_loaded('igbinary'), RuntimeException::class, 'igbinary extension is not loaded');
    }

    public function encode(mixed $value): string
    {
        return igbinary_serialize($value);
    }

    public function decode(string $value): mixed
    {
        return igbinary_unserialize($value);
    }
}
