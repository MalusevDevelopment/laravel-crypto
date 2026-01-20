<?php

declare(strict_types=1);

namespace CodeLieutenant\LaravelCrypto\Signing\Hmac;

use CodeLieutenant\LaravelCrypto\Contracts\KeyLoader;
use CodeLieutenant\LaravelCrypto\Contracts\Signing as SigningContract;
use CodeLieutenant\LaravelCrypto\Signing\Traits\Signing;

final readonly class Blake2b implements SigningContract
{
    use Signing;

    public function __construct(
        private KeyLoader $loader,
        private int $outputSize
    ) {}

    public function signRaw(string $data): string
    {
        return sodium_crypto_generichash($data, $this->loader->getKey(), $this->outputSize);
    }
}
