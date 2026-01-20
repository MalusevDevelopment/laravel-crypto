<?php

declare(strict_types=1);

use CodeLieutenant\LaravelCrypto\Encryption\Encrypter as LibEncrypter;
use CodeLieutenant\LaravelCrypto\Enums\Encryption;
use Illuminate\Encryption\Encrypter;
use Illuminate\Support\Facades\Config;

test('encrypter resolver', function (string $cipher, string $instance): void {
    if (str_starts_with($cipher, 'Sodium_') && !LibEncrypter::supported(str_repeat('0', Encryption::tryFrom($cipher)?->keySize() ?? 32), $cipher)) {
        $this->markTestSkipped("Cipher $cipher is not supported in this environment.");
    }

    Config::set('app.cipher', $cipher);

    $encrypter = $this->app->make('encrypter');

    expect($encrypter)->toBeInstanceOf($instance);
})->with([
    ['AES-256-GCM', Encrypter::class],
    ['AES-256-CBC', Encrypter::class],
    [Encryption::SodiumAES256GCM->value, LibEncrypter::class],
    [Encryption::SodiumXChaCha20Poly1305->value, LibEncrypter::class],
    [Encryption::SodiumAEGIS128LGCM->value, LibEncrypter::class],
    [Encryption::SodiumAEGIS256GCM->value, LibEncrypter::class],
]);
