<?php

declare(strict_types=1);

namespace CodeLieutenant\LaravelCrypto\Support;

use Random\Randomizer;

final readonly class Random
{
    public function __construct(
        private Randomizer $randomizer
    ) {}

    public function bytes(int $length): string
    {
        return $this->randomizer->getBytes($length);
    }

    public function string(int $length): string
    {
        return Base64::urlEncodeNoPadding($this->randomizer
            ->getBytes(Base64::encodedLength($length)),
        );
    }

    public function int(int $min = PHP_INT_MIN, int $max = PHP_INT_MAX): int
    {
        return $this->randomizer->getInt($min, $max);
    }
}
