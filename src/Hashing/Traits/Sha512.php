<?php

declare(strict_types=1);

namespace CodeLieutenant\LaravelCrypto\Hashing\Traits;

trait Sha512
{
    private ?\CodeLieutenant\LaravelCrypto\Hashing\Sha512 $sha512 = null;

    public function sha512(string $data): string
    {
        return $this->createSha512Driver()->hash($data);
    }

    public function sha512Raw(string $data): string
    {
        return $this->createSha512Driver()->hashRaw($data);
    }

    public function sha512Verify(string $hash, string $data): bool
    {
        return $this->createSha512Driver()->verify($hash, $data);
    }

    public function sha512VerifyRaw(string $hash, string $data): bool
    {
        return $this->createSha512Driver()->verifyRaw($hash, $data);
    }

    public function createSha512Driver(): \CodeLieutenant\LaravelCrypto\Hashing\Sha512
    {
        if ($this->sha512 === null) {
            $this->sha512 = $this->container->make(Sha512::class);
        }

        return $this->sha512;
    }
}
