<?php

declare(strict_types=1);

use CodeLieutenant\LaravelCrypto\Keys\Generators\AppKeyGenerator;
use CodeLieutenant\LaravelCrypto\Keys\Loaders\AppKeyLoader;
use Illuminate\Contracts\Config\Repository;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\File;

beforeEach(function (): void {
    $this->tempEnvFile = tempnam(sys_get_temp_dir(), 'env_');
    File::put($this->tempEnvFile, "APP_KEY=\nAPP_PREVIOUS_KEYS=\n");
});

afterEach(function (): void {
    if (File::exists($this->tempEnvFile)) {
        File::delete($this->tempEnvFile);
    }
});

test('it generates and updates previous keys', function (): void {
    $config = $this->app->make(Repository::class);
    $generator = new AppKeyGenerator($config);

    // 1. Initial generation (no existing key)
    Config::set('app.key', '');
    Config::set('app.cipher', 'AES-256-GCM');
    Config::set(AppKeyLoader::CONFIG_PREVIOUS_KEYS_PATH, '');

    $generator->generate($this->tempEnvFile);

    $newKey1 = Config::get('app.key');
    expect($newKey1)->toStartWith('base64:');

    $envContent = File::get($this->tempEnvFile);
    expect($envContent)->toContain("APP_KEY=$newKey1")
        ->and($envContent)->toContain('APP_PREVIOUS_KEYS=')
        ->and($envContent)->not->toContain('APP_PREVIOUS_KEYS=base64');

    // 2. Second generation - old key should move to APP_PREVIOUS_KEYS
    $generator->generate($this->tempEnvFile);

    $newKey2 = Config::get('app.key');
    expect($newKey2)->not->toBe($newKey1);

    $envContent = File::get($this->tempEnvFile);
    expect($envContent)->toContain("APP_KEY=$newKey2")
        ->and($envContent)->toContain("APP_PREVIOUS_KEYS=$newKey1");

    // 3. Third generation - should prepend
    $generator->generate($this->tempEnvFile);
    $newKey3 = Config::get('app.key');

    $envContent = File::get($this->tempEnvFile);
    expect($envContent)->toContain("APP_KEY=$newKey3")
        ->and($envContent)->toContain("APP_PREVIOUS_KEYS=$newKey2,$newKey1");
});

test('it returns new key when write is null', function (): void {
    $config = $this->app->make(Repository::class);
    $generator = new AppKeyGenerator($config);

    Config::set('app.key', 'old-key');
    Config::set('app.cipher', 'AES-256-GCM');

    $newKey = $generator->generate(null);
    expect($newKey)->toStartWith('base64:')
        ->and($newKey)->not->toBe('old-key');

    // Config should NOT be updated
    expect(Config::get('app.key'))->toBe('old-key');
});
