<?php

declare(strict_types=1);

use CodeLieutenant\LaravelCrypto\Keys\Generators\HmacKeyGenerator;
use CodeLieutenant\LaravelCrypto\Keys\Loaders\HmacKeyLoader;
use Illuminate\Contracts\Config\Repository;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\File;

beforeEach(function (): void {
    $this->tempEnvFile = tempnam(sys_get_temp_dir(), 'env_');
    File::put($this->tempEnvFile, "CRYPTO_HMAC_KEY=\n");
});

afterEach(function (): void {
    if (File::exists($this->tempEnvFile)) {
        File::delete($this->tempEnvFile);
    }
});

test('it generates and updates hmac key', function (): void {
    $config = $this->app->make(Repository::class);
    $generator = new HmacKeyGenerator($config);

    Config::set('crypto.signing.keys.hmac', '');

    $generator->generate($this->tempEnvFile);

    $newKey = Config::get('crypto.signing.keys.hmac');
    expect($newKey)->toStartWith('base64:');

    $envContent = File::get($this->tempEnvFile);
    expect($envContent)->toContain("CRYPTO_HMAC_KEY=$newKey");
});

test('it returns new hmac key when write is null', function (): void {
    $config = $this->app->make(Repository::class);
    $generator = new HmacKeyGenerator($config);

    Config::set('crypto.signing.keys.hmac', 'old-key');

    $newKey = $generator->generate(null);
    expect($newKey)->toStartWith('base64:')
        ->and($newKey)->not->toBe('old-key');

    expect(Config::get('crypto.signing.keys.hmac'))->toBe($newKey);
});

test('it loads hmac key', function (): void {
    Config::set('crypto.signing.keys.hmac', 'base64:'.base64_encode('test-key'));
    
    $loader = HmacKeyLoader::make($this->app->make(Repository::class));
    
    expect($loader->getKey())->toBe('test-key');
});
