<?php

declare(strict_types=1);

namespace CodeLieutenant\LaravelCrypto\Signing\Traits;

use CodeLieutenant\LaravelCrypto\Support\Base64;
use CodeLieutenant\LaravelCrypto\Traits\ConstantTimeCompare;

trait Signing
{
    use ConstantTimeCompare;

    public function verify(string $message, string $hmac, bool $decodeSignature = true): bool
    {
        return $this->equals(
            $this->signRaw($message),
            $decodeSignature ? Base64::constantUrlDecodeNoPadding($hmac) : $hmac
        );
    }

    public function sign(string $data): string
    {
        return Base64::constantUrlEncodeNoPadding($this->signRaw($data));
    }
}
