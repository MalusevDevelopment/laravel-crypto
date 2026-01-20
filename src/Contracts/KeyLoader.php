<?php

declare(strict_types=1);

namespace CodeLieutenant\LaravelCrypto\Contracts;

interface KeyLoader
{
    public function getKey(): string|array;
}
