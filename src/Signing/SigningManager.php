<?php

declare(strict_types=1);

namespace CodeLieutenant\LaravelCrypto\Signing;

use CodeLieutenant\LaravelCrypto\Contracts\Signing;
use CodeLieutenant\LaravelCrypto\Signing\Traits\Blake2b;
use CodeLieutenant\LaravelCrypto\Signing\Traits\EdDSA;
use CodeLieutenant\LaravelCrypto\Signing\Traits\Hmac256;
use CodeLieutenant\LaravelCrypto\Signing\Traits\Hmac512;
use Illuminate\Support\Manager;

class SigningManager extends Manager implements Signing
{
    use Blake2b;
    use EdDSA;
    use Hmac256;
    use Hmac512;

    public function sign(string $data): string
    {
        return $this->driver()->sign($data);
    }

    public function signRaw(string $data): string
    {
        return $this->driver()->signRaw($data);
    }

    public function verify(string $message, string $hmac, bool $decodeSignature = true): bool
    {
        return $this->driver()->verify($message, $hmac, $decodeSignature);
    }

    public function getDefaultDriver()
    {
        return $this->config->get('crypto.signing.driver', 'blake2b');
    }
}
