<?php

declare(strict_types=1);

namespace CodeLieutenant\LaravelCrypto\Keys\Loaders;

use CodeLieutenant\LaravelCrypto\Contracts\KeyLoader;
use Illuminate\Contracts\Config\Repository;
use Illuminate\Encryption\MissingAppKeyException;
use Psr\Log\LoggerInterface;
use RuntimeException;
use SplFileObject;

class EdDSASignerKeyLoader implements KeyLoader
{
    public const KEY_LENGTH = SODIUM_CRYPTO_SIGN_KEYPAIRBYTES;

    public const PUBLIC_KEY_LENGTH = SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES;

    public const PRIVATE_KEY_LENGTH = SODIUM_CRYPTO_SIGN_SECRETKEYBYTES;

    private const string CONFIG_KEY_PATH = 'crypto.signing.keys.eddsa';

    private static string $privateKey;

    private static string $publicKey;

    public static function make(Repository $config, LoggerInterface $logger): static
    {
        if (! isset(self::$publicKey, self::$privateKey)) {
            $path = $config->get(self::CONFIG_KEY_PATH);

            throw_if($path === null, MissingAppKeyException::class, 'File for EdDSA signer is not set');

            [self::$publicKey, self::$privateKey] = static::parseKeys($path, $logger);
        }

        return new static;
    }

    /**
     * @return array<int, string|bool>
     */
    protected static function parseKeys(string $keyPath, LoggerInterface $logger): array
    {
        $file = new SplFileObject($keyPath, 'rb');
        throw_if($file->flock(LOCK_SH) === false, RuntimeException::class, 'Error while locking file (shared/reading)');

        try {
            $keys = $file->fread(self::KEY_LENGTH * 2 + 1);

            throw_if($keys === false, RuntimeException::class, 'Error while reading key');
        } finally {
            if ($file->flock(LOCK_UN) === false) {
                $logger->warning('Error while unlocking file');
            }
        }

        [$publicKey, $privateKey] = explode(PHP_EOL, $keys, 2);

        return [hex2bin($publicKey), hex2bin($privateKey)];
    }

    /**
     * @return array<int, string>
     */
    public function getKey(): string|array
    {
        return [self::$publicKey, self::$privateKey];
    }
}
