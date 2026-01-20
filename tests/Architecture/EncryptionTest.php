<?php

declare(strict_types=1);

use Illuminate\Contracts\Encryption\Encrypter;
use Illuminate\Contracts\Encryption\StringEncrypter;

arch('encryption')
    ->expect('CodeLieutenant\LaravelCrypto\Encryption')
    ->toOnlyImplement([Encrypter::class, StringEncrypter::class])
    ->toBeClasses()
    ->toHaveSuffix('Encrypter')
    ->toBeFinal();
