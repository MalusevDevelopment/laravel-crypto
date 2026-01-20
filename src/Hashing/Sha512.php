<?php

declare(strict_types=1);

namespace CodeLieutenant\LaravelCrypto\Hashing;

use CodeLieutenant\LaravelCrypto\Contracts\Hashing;
use CodeLieutenant\LaravelCrypto\Hashing\Traits\Hash;
use CodeLieutenant\LaravelCrypto\Traits\ConstantTimeCompare;

final class Sha512 implements Hashing
{
    use ConstantTimeCompare;
    use Hash;

    public const string ALGORITHM = 'sha512';

    public function hash(string $data): string
    {
        return hash(self::ALGORITHM, $data);
    }

    public function hashRaw(string $data): string
    {
        return hash(self::ALGORITHM, $data, true);
    }
}
