<?php

declare(strict_types=1);

namespace CodeLieutenant\LaravelCrypto\Contracts;

interface Signing
{
    /**
     * Sign the data and return the signature as a base64 url encoded string
     */
    public function sign(string $data): string;

    /**
     * Sign the data and return the signature as a raw string (binary)
     */
    public function signRaw(string $data): string;

    /**
     * Verify the signature against the $message
     */
    public function verify(string $message, string $hmac, bool $decodeSignature = true): bool;
}
