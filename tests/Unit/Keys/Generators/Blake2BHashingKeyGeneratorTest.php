<?php

declare(strict_types=1);

use CodeLieutenant\LaravelCrypto\Keys\Generators\Blake2BHashingKeyGenerator;
use CodeLieutenant\LaravelCrypto\Keys\Loaders\Blake2BHashingKeyLoader;
use Illuminate\Contracts\Config\Repository;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\File;

beforeEach(function (): void {
    $this->tempEnvFile = tempnam(sys_get_temp_dir(), 'env_');
    File::put($this->tempEnvFile, "CRYPTO_BLAKE2B_HASHING_KEY=\n");
});

afterEach(function (): void {
    if (File::exists($this->tempEnvFile)) {
        File::delete($this->tempEnvFile);
    }
});

test('it generates and updates blake2b key', function (): void {
    $config = $this->app->make(Repository::class);
    $generator = new Blake2BHashingKeyGenerator($config);

    Config::set('crypto.hashing.config.blake2b.key', '');

    $generator->generate($this->tempEnvFile);

    $newKey = Config::get('crypto.hashing.config.blake2b.key');
    expect($newKey)->toStartWith('base64:');

    $envContent = File::get($this->tempEnvFile);
    expect($envContent)->toContain("CRYPTO_BLAKE2B_HASHING_KEY=$newKey");
});

test('it returns new blake2b key when write is null', function (): void {
    $config = $this->app->make(Repository::class);
    $generator = new Blake2BHashingKeyGenerator($config);

    Config::set('crypto.hashing.config.blake2b.key', 'old-key');

    $newKey = $generator->generate(null);
    expect($newKey)->toStartWith('base64:')
        ->and($newKey)->not->toBe('old-key');

    // HashingKeyGenerator UPDATES config even if write is null
    expect(Config::get('crypto.hashing.config.blake2b.key'))->toBe($newKey);
});

test('it loads blake2b key', function (): void {
    Config::set('crypto.hashing.config.blake2b.key', 'base64:'.base64_encode('test-key'));
    
    $loader = Blake2BHashingKeyLoader::make($this->app->make(Repository::class));
    
    expect($loader->getKey())->toBe('test-key');
});
