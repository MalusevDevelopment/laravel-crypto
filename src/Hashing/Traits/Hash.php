<?php

declare(strict_types=1);

namespace CodeLieutenant\LaravelCrypto\Hashing\Traits;

trait Hash
{
    public function verify(string $hash, string $data): bool
    {
        return $this->equals($hash, $this->hash($data));
    }

    public function verifyRaw(string $hash, string $data): bool
    {
        return $this->equals($hash, $this->hashRaw($data));
    }
}
