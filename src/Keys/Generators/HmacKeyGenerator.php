<?php

declare(strict_types=1);

namespace CodeLieutenant\LaravelCrypto\Keys\Generators;

final class HmacKeyGenerator extends HashingKeyGenerator
{
    protected static string $ENV = 'CRYPTO_HMAC_KEY';

    protected static string $CONFIG_KEY_PATH = 'crypto.signing.keys.hmac';
}
