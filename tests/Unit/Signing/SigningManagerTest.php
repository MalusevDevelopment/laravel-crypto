<?php

declare(strict_types=1);

use CodeLieutenant\LaravelCrypto\Signing\EdDSA\EdDSA;
use CodeLieutenant\LaravelCrypto\Signing\Hmac\Blake2b as HmacBlake2b;
use CodeLieutenant\LaravelCrypto\Signing\Hmac\Sha256 as HmacSha256;
use CodeLieutenant\LaravelCrypto\Signing\Hmac\Sha512 as HmacSha512;
use CodeLieutenant\LaravelCrypto\Signing\SigningManager;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\File;

beforeEach(function (): void {
    $this->hmacKey = str_repeat('k', 32);
    Config::set('crypto.signing.keys.hmac', 'base64:'.base64_encode($this->hmacKey));

    $this->tempKeyFile = tempnam(sys_get_temp_dir(), 'eddsa_');
    $keyPair = sodium_crypto_sign_keypair();
    $privateKey = bin2hex(sodium_crypto_sign_secretkey($keyPair));
    $publicKey = bin2hex(sodium_crypto_sign_publickey($keyPair));
    File::put($this->tempKeyFile, $publicKey.PHP_EOL.$privateKey);
    Config::set('crypto.signing.keys.eddsa', $this->tempKeyFile);
});

afterEach(function (): void {
    if (File::exists($this->tempKeyFile)) {
        File::delete($this->tempKeyFile);
    }
});

test('signing manager can use different drivers', function (string $driver, string $class): void {
    Config::set('crypto.signing.driver', $driver);
    Config::set('crypto.signing.config.'.HmacBlake2b::class, 32);

    $manager = $this->app->make(SigningManager::class);

    expect($manager->driver())->toBeInstanceOf($class);

    $data = 'test data';
    $signature = $manager->sign($data);
    expect($manager->verify($data, $signature))->toBeTrue();
})->with([
    ['blake2b', HmacBlake2b::class],
    ['hmac256', HmacSha256::class],
    ['hmac512', HmacSha512::class],
    ['eddsa', EdDSA::class],
]);

test('signing manager direct trait methods', function (): void {
    Config::set('crypto.signing.config.'.HmacBlake2b::class, 32);
    $manager = $this->app->make(SigningManager::class);
    $data = 'test data';

    $sig = $manager->blake2bSign($data);
    expect($manager->blake2bVerify($data, $sig))->toBeTrue();

    $sig = $manager->hmac256Sign($data);
    expect($manager->hmac256Verify($data, $sig))->toBeTrue();

    $sig = $manager->hmac512Sign($data);
    expect($manager->hmac512Verify($data, $sig))->toBeTrue();

    $sig = $manager->eddsaSign($data);
    expect($manager->eddsaVerify($data, $sig))->toBeTrue();
});
