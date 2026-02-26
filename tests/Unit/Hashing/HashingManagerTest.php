<?php

declare(strict_types=1);

use CodeLieutenant\LaravelCrypto\Hashing\HashingManager;
use CodeLieutenant\LaravelCrypto\Hashing\Blake2b;
use CodeLieutenant\LaravelCrypto\Hashing\Sha256;
use CodeLieutenant\LaravelCrypto\Hashing\Sha512;
use Illuminate\Support\Facades\Config;

test('hashing manager can use different drivers', function (string $driver, string $class): void {
    Config::set('crypto.hashing.driver', $driver);
    $manager = $this->app->make(HashingManager::class);
    
    expect($manager->driver())->toBeInstanceOf($class);
    
    $data = 'test data';
    $hash = $manager->hash($data);
    expect($manager->verify($hash, $data))->toBeTrue();
})->with([
    ['blake2b', Blake2b::class],
    ['sha256', Sha256::class],
    ['sha512', Sha512::class],
]);

test('hashing manager direct trait methods', function (): void {
    $manager = $this->app->make(HashingManager::class);
    $data = 'test data';
    
    $hash = $manager->blake2b($data);
    expect($manager->blake2bVerify($hash, $data))->toBeTrue();
    
    $hash = $manager->sha256($data);
    expect($manager->sha256Verify($hash, $data))->toBeTrue();
    
    $hash = $manager->sha512($data);
    expect($manager->sha512Verify($hash, $data))->toBeTrue();
});
