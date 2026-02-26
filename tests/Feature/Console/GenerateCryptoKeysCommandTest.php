<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\File;

beforeEach(function (): void {
    $this->tempEnvFile = tempnam(sys_get_temp_dir(), 'env_');
    File::put($this->tempEnvFile, "APP_KEY=\nCRYPTO_BLAKE2B_HASHING_KEY=\nCRYPTO_HMAC_KEY=\n");
    
    $this->tempKeyFile = tempnam(sys_get_temp_dir(), 'eddsa_');
    Config::set('crypto.signing.keys.eddsa', $this->tempKeyFile);
    
    // Mock environment file path
    $this->app->instance('path.environment', $this->tempEnvFile);
    $this->app->useEnvironmentPath(dirname($this->tempEnvFile));
    $this->app->loadEnvironmentFrom(basename($this->tempEnvFile));
});

afterEach(function (): void {
    if (File::exists($this->tempEnvFile)) {
        File::delete($this->tempEnvFile);
    }
    if (File::exists($this->tempKeyFile)) {
        File::delete($this->tempKeyFile);
    }
});

test('it can show keys without writing to file', function (): void {
    Artisan::call('crypto:keys', ['--show' => true]);
    
    $output = Artisan::output();
    expect($output)->toContain('EdDSA Key:')
        ->and($output)->toContain('App Key:')
        ->and($output)->toContain('Blake2b Key:')
        ->and($output)->toContain('HMAC Key:');
        
    // Env file should be empty (only placeholders)
    $content = File::get($this->tempEnvFile);
    expect($content)->toBe("APP_KEY=\nCRYPTO_BLAKE2B_HASHING_KEY=\nCRYPTO_HMAC_KEY=\n");
});

test('it can generate and write keys to file', function (): void {
    $code = Artisan::call('crypto:keys', ['--force' => true]);
    expect($code)->toBe(0);
    
    $content = File::get($this->tempEnvFile);
    expect($content)->toContain('APP_KEY=base64:')
        ->and($content)->toContain('CRYPTO_BLAKE2B_HASHING_KEY=base64:')
        ->and($content)->toContain('CRYPTO_HMAC_KEY=base64:')
        ->and(File::exists($this->tempKeyFile))->toBeTrue()
        ->and(File::get($this->tempKeyFile))->not->toBeEmpty();
});

test('it can skip specific keys', function (): void {
    Artisan::call('crypto:keys', [
        '--force' => true,
        '--no-app' => true,
        '--no-eddsa' => true,
    ]);
    
    $content = File::get($this->tempEnvFile);
    expect($content)->not->toContain('APP_KEY=base64:')
        ->and($content)->toContain('CRYPTO_BLAKE2B_HASHING_KEY=base64:')
        ->and($content)->toContain('CRYPTO_HMAC_KEY=base64:')
        ->and(File::get($this->tempKeyFile))->toBeEmpty();
});
