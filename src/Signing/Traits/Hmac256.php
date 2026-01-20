<?php

declare(strict_types=1);

namespace CodeLieutenant\LaravelCrypto\Signing\Traits;

use CodeLieutenant\LaravelCrypto\Signing\Hmac\Sha256;

trait Hmac256
{
    protected ?Sha256 $hmac256 = null;

    public function hmac256Sign(string $data): string
    {
        return $this->createHmac256Driver()->sign($data);
    }

    public function hmac256SignRaw(string $data): string
    {
        return $this->createHmac256Driver()->signRaw($data);
    }

    public function hmac256Verify(string $message, string $hmac): bool
    {
        return $this->createHmac256Driver()->verify($message, $hmac);
    }

    public function createHmac256Driver(): Sha256
    {
        if ($this->hmac256 === null) {
            $this->hmac256 = $this->container->get(Sha256::class);
        }

        return $this->hmac256;
    }
}
