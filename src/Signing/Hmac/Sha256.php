<?php

declare(strict_types=1);

namespace CodeLieutenant\LaravelCrypto\Signing\Hmac;

use CodeLieutenant\LaravelCrypto\Contracts\KeyLoader;
use CodeLieutenant\LaravelCrypto\Contracts\Signing as SigningContract;
use CodeLieutenant\LaravelCrypto\Signing\Traits\Signing;
use CodeLieutenant\LaravelCrypto\Support\Base64;

final readonly class Sha256 implements SigningContract
{
    use Signing;

    public function __construct(
        private KeyLoader $loader,
    ) {}

    public function signRaw(string $data): string
    {
        return sodium_crypto_auth($data, $this->loader->getKey());
    }

    public function verify(string $message, string $hmac, bool $decodeSignature = true): bool
    {
        return sodium_crypto_auth_verify(
            $decodeSignature ? Base64::constantUrlDecodeNoPadding($hmac) : $hmac,
            $message,
            $this->loader->getKey()
        );
    }
}
