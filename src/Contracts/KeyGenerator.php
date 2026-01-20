<?php

declare(strict_types=1);

namespace CodeLieutenant\LaravelCrypto\Contracts;

interface KeyGenerator
{
    public function generate(?string $write): ?string;
}
