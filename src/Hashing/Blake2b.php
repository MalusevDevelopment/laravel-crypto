<?php

declare(strict_types=1);

namespace CodeLieutenant\LaravelCrypto\Hashing;

use CodeLieutenant\LaravelCrypto\Contracts\Hashing;
use CodeLieutenant\LaravelCrypto\Hashing\Traits\Hash;
use CodeLieutenant\LaravelCrypto\Support\Base64;
use CodeLieutenant\LaravelCrypto\Traits\ConstantTimeCompare;

final readonly class Blake2b implements Hashing
{
    use ConstantTimeCompare;
    use Hash;

    public const string ALGORITHM = 'blake2b';

    public function __construct(
        private ?string $key = null,
        private int $outputLength = 64,
    ) {}

    public function hash(string $data): string
    {
        return Base64::urlEncodeNoPadding($this->hashRaw($data));
    }

    public function hashRaw(string $data): string
    {
        return sodium_crypto_generichash($data, $this->key ?? '', $this->outputLength);
    }
}
