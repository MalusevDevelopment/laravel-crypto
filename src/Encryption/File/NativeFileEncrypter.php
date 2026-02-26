<?php

declare(strict_types=1);

namespace CodeLieutenant\LaravelCrypto\Encryption\File;

use CodeLieutenant\LaravelCrypto\Contracts\EncrypterProvider;
use CodeLieutenant\LaravelCrypto\Contracts\FileEncrypter;
use CodeLieutenant\LaravelCrypto\Traits\StreamEncryptionTrait;
use SensitiveParameter;

final readonly class NativeFileEncrypter implements FileEncrypter
{
    use StreamEncryptionTrait;

    public function __construct(private EncrypterProvider $provider)
    {
    }

    public function nonceSize(): int
    {
        return $this->provider->nonceSize();
    }

    public function tagSize(): int
    {
        return $this->provider->tagSize();
    }

    public function encryptChunk(#[SensitiveParameter] string $key, string $chunk, string $nonce): string
    {
        return $this->provider->encryptChunk($key, $chunk, $nonce);
    }

    public function decryptChunk(#[SensitiveParameter] string $key, string $chunk, string $nonce): string
    {
        return $this->provider->decryptChunk($key, $chunk, $nonce);
    }
}
