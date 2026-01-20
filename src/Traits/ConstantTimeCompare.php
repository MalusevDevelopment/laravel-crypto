<?php

declare(strict_types=1);

namespace CodeLieutenant\LaravelCrypto\Traits;

trait ConstantTimeCompare
{
    public function equals(string $hash1, string $hash2): bool
    {
        return hash_equals($hash1, $hash2);
    }
}
