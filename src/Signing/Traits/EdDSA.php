<?php

declare(strict_types=1);

namespace CodeLieutenant\LaravelCrypto\Signing\Traits;

trait EdDSA
{
    protected ?\CodeLieutenant\LaravelCrypto\Signing\EdDSA\EdDSA $eddsa = null;

    public function eddsaSign(string $data): string
    {
        return $this->createEdDSADriver()->sign($data);
    }

    public function eddsaSignRaw(string $data): string
    {
        return $this->createEdDSADriver()->signRaw($data);
    }

    public function eddsaVerify(string $message, string $hmac): bool
    {
        return $this->createEdDSADriver()->verify($message, $hmac);
    }

    public function createEdDSADriver(): \CodeLieutenant\LaravelCrypto\Signing\EdDSA\EdDSA
    {
        if ($this->eddsa === null) {
            $this->eddsa = $this->container->get(EdDSA::class);
        }

        return $this->eddsa;
    }
}
