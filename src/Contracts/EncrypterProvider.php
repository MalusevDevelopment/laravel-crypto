<?php

declare(strict_types=1);

namespace CodeLieutenant\LaravelCrypto\Contracts;

use SensitiveParameter;

interface EncrypterProvider
{
    public function nonceSize(): int;

    public function encrypt(#[SensitiveParameter] string $key, #[SensitiveParameter] mixed $value, string $nonce): string;

    public function decrypt(#[SensitiveParameter] string $key, string $payload, string $nonce): mixed;
}
