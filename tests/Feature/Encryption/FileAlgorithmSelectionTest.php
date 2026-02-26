<?php

declare(strict_types=1);

namespace Tests\Feature\Encryption;

use CodeLieutenant\LaravelCrypto\Encryption\Encrypter;
use CodeLieutenant\LaravelCrypto\Encryption\File\NativeFileEncrypter;
use CodeLieutenant\LaravelCrypto\Encryption\File\SecretStreamFileEncrypter;
use CodeLieutenant\LaravelCrypto\Encryption\File\XSalsaHmacFileEncrypter;
use Illuminate\Support\Facades\Config;

it('uses secretstream by default', function () {
    /** @var Encrypter $encrypter */
    $encrypter = app('encrypter');

    // Using reflection to check private property
    $reflection = new \ReflectionClass($encrypter);
    $property = $reflection->getProperty('fileEncrypter');
    $property->setAccessible(true);

    expect($property->getValue($encrypter))->toBeInstanceOf(SecretStreamFileEncrypter::class);
});

it('can switch to native file encryption', function () {
    Config::set('crypto.file_encryption.driver', NativeFileEncrypter::class);

    // Re-register or resolve again if needed, but since it's a singleton we might need to swap it
    // In a real Laravel app, changing config might not affect already resolved singletons.
    // However, our ServiceProvider uses a closure for the singleton.

    // For the sake of this test, let's just manually trigger the logic from ServiceProvider or re-resolve.
    // Since it's a singleton, we need to forget it first if we want app('encrypter') to re-resolve.
    app()->forgetInstance('encrypter');
    app()->forgetInstance(Encrypter::class);

    /** @var Encrypter $encrypter */
    $encrypter = app('encrypter');

    $reflection = new \ReflectionClass($encrypter);
    $property = $reflection->getProperty('fileEncrypter');
    $property->setAccessible(true);

    expect($property->getValue($encrypter))->toBeInstanceOf(NativeFileEncrypter::class);
});

it('can switch to native file encryption using legacy string', function () {
    Config::set('crypto.file_encryption.driver', 'native');

    app()->forgetInstance('encrypter');
    app()->forgetInstance(Encrypter::class);

    /** @var Encrypter $encrypter */
    $encrypter = app('encrypter');

    $reflection = new \ReflectionClass($encrypter);
    $property = $reflection->getProperty('fileEncrypter');
    $property->setAccessible(true);

    expect($property->getValue($encrypter))->toBeInstanceOf(NativeFileEncrypter::class);
});

it('uses secretstream even if invalid driver is provided', function () {
    Config::set('crypto.file_encryption.driver', 'invalid');

    app()->forgetInstance('encrypter');
    app()->forgetInstance(Encrypter::class);

    /** @var Encrypter $encrypter */
    $encrypter = app('encrypter');

    $reflection = new \ReflectionClass($encrypter);
    $property = $reflection->getProperty('fileEncrypter');
    $property->setAccessible(true);

    expect($property->getValue($encrypter))->toBeInstanceOf(SecretStreamFileEncrypter::class);
});

it('can switch to xsalsa-hmac file encryption', function () {
    Config::set('crypto.file_encryption.driver', XSalsaHmacFileEncrypter::class);

    app()->forgetInstance('encrypter');
    app()->forgetInstance(Encrypter::class);

    /** @var Encrypter $encrypter */
    $encrypter = app('encrypter');

    $reflection = new \ReflectionClass($encrypter);
    $property = $reflection->getProperty('fileEncrypter');
    $property->setAccessible(true);

    expect($property->getValue($encrypter))->toBeInstanceOf(XSalsaHmacFileEncrypter::class);
});

it('can switch to xsalsa-hmac file encryption using legacy string', function () {
    Config::set('crypto.file_encryption.driver', 'xsalsa-hmac');

    app()->forgetInstance('encrypter');
    app()->forgetInstance(Encrypter::class);

    /** @var Encrypter $encrypter */
    $encrypter = app('encrypter');

    $reflection = new \ReflectionClass($encrypter);
    $property = $reflection->getProperty('fileEncrypter');
    $property->setAccessible(true);

    expect($property->getValue($encrypter))->toBeInstanceOf(XSalsaHmacFileEncrypter::class);
});
