<?php

declare(strict_types=1);

namespace CodeLieutenant\LaravelCrypto\Keys\Loaders;

class HmacKeyLoader extends AppKeyLoader
{
    public const CONFIG_KEY_PATH = 'crypto.signing.keys.hmac';
}
