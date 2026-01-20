<?php

declare(strict_types=1);

namespace CodeLieutenant\LaravelCrypto\Encoder;

use CodeLieutenant\LaravelCrypto\Contracts\Encoder;

class PhpEncoder implements Encoder
{
    /**
     * @var array<int|string, mixed>
     */
    private readonly array $options;

    public function __construct(...$options)
    {
        $this->options = $options;
    }

    public function encode(mixed $value): string
    {
        return serialize($value);
    }

    public function decode(string $value): mixed
    {
        return unserialize($value, $this->options);
    }
}
