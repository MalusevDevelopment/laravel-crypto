<?php

declare(strict_types=1);

namespace CodeLieutenant\LaravelCrypto\Encoder;

use CodeLieutenant\LaravelCrypto\Contracts\Encoder;

class JsonEncoder implements Encoder
{
    public function __construct(private readonly bool $asArray = true) {}

    public function encode(mixed $value): string
    {
        return json_encode($value, JSON_THROW_ON_ERROR);
    }

    public function decode(string $value): mixed
    {
        return json_decode(
            $value,
            $this->asArray,
            512,
            JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE
        );
    }
}
