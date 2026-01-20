<?php

declare(strict_types=1);

namespace CodeLieutenant\LaravelCrypto\Keys\Loaders;

class Blake2BHashingKeyLoader extends AppKeyLoader
{
    public const CONFIG_KEY_PATH = 'crypto.signing.keys.hmac';
}
