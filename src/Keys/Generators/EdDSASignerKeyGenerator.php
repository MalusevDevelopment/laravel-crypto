<?php

declare(strict_types=1);

namespace CodeLieutenant\LaravelCrypto\Keys\Generators;

use CodeLieutenant\LaravelCrypto\Contracts\KeyGenerator;
use Illuminate\Contracts\Config\Repository;
use Illuminate\Support\Facades\File;
use Psr\Log\LoggerInterface;
use RuntimeException;
use SplFileObject;

final readonly class EdDSASignerKeyGenerator implements KeyGenerator
{
    private const string CONFIG_KEY_PATH = 'crypto.signing.keys.eddsa';

    public function __construct(
        private Repository $config,
        private LoggerInterface $logger,
    ) {}

    public function generate(?string $write): ?string
    {
        $keyPair = sodium_crypto_sign_keypair();
        $privateKey = bin2hex(sodium_crypto_sign_secretkey($keyPair));
        $publicKey = bin2hex(sodium_crypto_sign_publickey($keyPair));

        $key = implode(PHP_EOL, [$publicKey, $privateKey]);

        if ($write === null) {
            return $key;
        }

        $path = $this->config->get(self::CONFIG_KEY_PATH);

        throw_if($path === null, RuntimeException::class, 'File for EdDSA signer is not set');

        File::ensureDirectoryExists(dirname($path), mode: 0740);

        $file = new SplFileObject($path, 'wb');

        throw_if($file->flock(LOCK_EX) === false, RuntimeException::class, 'Error while locking file (exclusive/writing)');

        try {
            throw_if($file->fwrite($key) === false, RuntimeException::class, 'Error while writing public key to file');
        } finally {
            if ($file->flock(LOCK_UN) === false) {
                $this->logger->warning('Error while unlocking file');
            }

            sodium_memzero($privateKey);
            sodium_memzero($publicKey);
            sodium_memzero($keyPair);
            sodium_memzero($key);
        }

        return null;
    }
}
