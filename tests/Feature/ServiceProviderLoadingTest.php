<?php

declare(strict_types=1);

use CodeLieutenant\LaravelCrypto\Encryption\AesGcm256Encrypter;
use CodeLieutenant\LaravelCrypto\Encryption\XChaCha20Poly1305Encrypter;
use CodeLieutenant\LaravelCrypto\Enums\Encryption;
use Illuminate\Encryption\Encrypter;
use Illuminate\Support\Facades\Config;

test('encrypter resolver', function (string $cipher, string $instance): void {
    Config::set('app.cipher', $cipher);

    $encrypter = $this->app->make('encrypter');

    expect($encrypter)->toBeInstanceOf($instance);
})->with([
    ['AES-256-GCM', Encrypter::class],
    ['AES-256-CBC', Encrypter::class],
    [Encryption::SodiumAES256GCM->value, AesGcm256Encrypter::class],
    [Encryption::SodiumXChaCha20Poly1305->value, XChaCha20Poly1305Encrypter::class],
]);
