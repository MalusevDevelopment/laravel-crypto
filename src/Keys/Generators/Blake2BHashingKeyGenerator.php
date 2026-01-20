<?php

declare(strict_types=1);

namespace CodeLieutenant\LaravelCrypto\Keys\Generators;

final class Blake2BHashingKeyGenerator extends HashingKeyGenerator
{
    protected static int $KEY_SIZE = 32;

    protected static string $ENV = 'CRYPTO_BLAKE2B_HASHING_KEY';

    protected static string $CONFIG_KEY_PATH = 'crypto.hashing.config.blake2b.key';
}
