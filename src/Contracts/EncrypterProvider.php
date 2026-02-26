<?php

declare(strict_types=1);

namespace CodeLieutenant\LaravelCrypto\Contracts;

use SensitiveParameter;

interface EncrypterProvider
{
    public const int CHUNK_SIZE = 8192;

    public const int HMAC_SIZE = 32;

    public const string HMAC_ALGORITHM = 'sha512/256';

    public function nonceSize(): int;

    public function encrypt(#[SensitiveParameter] string $key, #[SensitiveParameter] mixed $value, string $nonce): string;

    public function decrypt(#[SensitiveParameter] string $key, string $payload, string $nonce): mixed;

    public function tagSize(): int;

    public function encryptChunk(#[SensitiveParameter] string $key, string $chunk, string $nonce): string;

    public function decryptChunk(#[SensitiveParameter] string $key, string $chunk, string $nonce): string;
}
