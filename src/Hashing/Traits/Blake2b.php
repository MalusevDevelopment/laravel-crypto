<?php

declare(strict_types=1);

namespace CodeLieutenant\LaravelCrypto\Hashing\Traits;

use CodeLieutenant\LaravelCrypto\Hashing\Blake2b as Blake2bHashing;

trait Blake2b
{
    protected ?Blake2bHashing $blake2b = null;

    public function blake2b(string $data): string
    {
        return $this->createBlake2bDriver()->hash($data);
    }

    public function blake2bRaw(string $data): string
    {
        return $this->createBlake2bDriver()->hashRaw($data);
    }

    public function blake2bVerify(string $hash, string $data): bool
    {
        return $this->createBlake2bDriver()->verify($hash, $data);
    }

    public function blake2bVerifyRaw(string $hash, string $data): bool
    {
        return $this->createBlake2bDriver()->verifyRaw($hash, $data);
    }

    public function createBlake2bDriver(): Blake2bHashing
    {
        if ($this->blake2b === null) {
            $this->blake2b = $this->container->make(Blake2b::class);
        }

        return $this->blake2b;
    }
}
