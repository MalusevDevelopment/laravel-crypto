<?php

declare(strict_types=1);

use CodeLieutenant\LaravelCrypto\Contracts\EncrypterProvider;
use Illuminate\Contracts\Encryption\Encrypter;
use Illuminate\Contracts\Encryption\StringEncrypter;

arch('encryption')
    ->expect(\CodeLieutenant\LaravelCrypto\Encryption\Encrypter::class)
    ->toOnlyImplement([Encrypter::class, StringEncrypter::class])
    ->toBeClasses()
    ->toHaveSuffix('Encrypter')
    ->toBeFinal();

arch('encryption providers')
    ->expect('CodeLieutenant\LaravelCrypto\Encryption\Providers')
    ->toOnlyImplement(EncrypterProvider::class)
    ->toBeClasses()
    ->toHaveSuffix('Encrypter')
    ->toBeFinal();
