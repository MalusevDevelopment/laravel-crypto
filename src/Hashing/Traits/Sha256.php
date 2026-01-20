<?php

declare(strict_types=1);

namespace CodeLieutenant\LaravelCrypto\Hashing\Traits;

trait Sha256
{
    private ?\CodeLieutenant\LaravelCrypto\Hashing\Sha256 $sha256 = null;

    public function sha256(string $data): string
    {
        return $this->createSha256Driver()->hash($data);
    }

    public function sha256Raw(string $data): string
    {
        return $this->createSha256Driver()->hashRaw($data);
    }

    public function sha256Verify(string $hash, string $data): bool
    {
        return $this->createSha256Driver()->verify($hash, $data);
    }

    public function sha256VerifyRaw(string $hash, string $data): bool
    {
        return $this->createSha256Driver()->verifyRaw($hash, $data);
    }

    public function createSha256Driver(): \CodeLieutenant\LaravelCrypto\Hashing\Sha256
    {
        if ($this->sha256 === null) {
            $this->sha256 = $this->container->make(Sha256::class);
        }

        return $this->sha256;
    }
}
