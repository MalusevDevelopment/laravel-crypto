<?php

declare(strict_types=1);

namespace CodeLieutenant\LaravelCrypto\Keys\Generators;

final class HmacKeyGenerator extends HashingKeyGenerator
{
    protected static int $KEY_SIZE = 32;

    protected static string $ENV = 'CRYPTO_HMAC_KEY';

    protected static string $CONFIG_KEY_PATH = 'crypto.signing.keys.hmac';
}
