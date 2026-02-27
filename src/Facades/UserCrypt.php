<?php

declare(strict_types=1);

namespace CodeLieutenant\LaravelCrypto\Facades;

use Illuminate\Support\Facades\Facade;

/**
 * Facade for the per-user encrypter (UserEncrypter).
 *
 * @method static string encrypt(mixed $value, bool $serialize = true)
 * @method static mixed decrypt(string $payload, bool $unserialize = true)
 * @method static string encryptString(string $value)
 * @method static string decryptString(string $payload)
 * @method static void encryptFile(string $inputFilePath, string $outputFilePath)
 * @method static void decryptFile(string $inputFilePath, string $outputFilePath)
 * @method static string blindIndex(string $value, string $column, bool $normalise = true)
 * @method static bool verifyBlindIndex(string $storedIndex, string $value, string $column, bool $normalise = true)
 * @method static bool hasContext()
 *
 * @see \CodeLieutenant\LaravelCrypto\Encryption\UserKey\UserEncrypter
 */
final class UserCrypt extends Facade
{
    protected static function getFacadeAccessor(): string
    {
        return 'user-crypt';
    }
}
