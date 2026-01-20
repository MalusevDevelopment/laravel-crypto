<?php

declare(strict_types=1);

namespace CodeLieutenant\LaravelCrypto\Facades;

use CodeLieutenant\LaravelCrypto\Hashing\HashingManager;
use Illuminate\Support\Facades\Facade;

/**
 * Class Hashing
 *
 *
 * @method static string hash(string $data)
 * @method static string hashRaw(string $data)
 * @method static boolean equals(string $hash1, string $hash2)
 * @method static string blake2b(string $data)
 * @method static string blake2bRaw(string $data)
 * @method static string sha256(string $data)
 * @method static string sha256Raw(string $data)
 * @method static string sha512(string $data)
 * @method static string sha512Raw(string $data)
 * @method static bool verify(string $hash, string $data)
 * @method static bool verifyRaw(string $hash, string $data)
 * @method static bool blake2bVerify(string $hash, string $data)
 * @method static bool blake2bVerifyRaw(string $hash, string $data)
 * @method static bool sha256Verify(string $hash, string $data)
 * @method static bool sha256VerifyRaw(string $hash, string $data)
 * @method static bool sha512Verify(string $hash, string $data)
 * @method static bool sha512VerifyRaw(string $hash, string $data)
 */
class Hashing extends Facade
{
    protected static function getFacadeAccessor(): string
    {
        return HashingManager::class;
    }
}
