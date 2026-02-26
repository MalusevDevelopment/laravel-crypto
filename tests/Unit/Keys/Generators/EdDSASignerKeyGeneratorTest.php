<?php

declare(strict_types=1);

use CodeLieutenant\LaravelCrypto\Keys\Generators\EdDSASignerKeyGenerator;
use CodeLieutenant\LaravelCrypto\Keys\Loaders\EdDSASignerKeyLoader;
use Illuminate\Contracts\Config\Repository;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\File;
use Psr\Log\LoggerInterface;

beforeEach(function (): void {
    $this->tempKeyFile = tempnam(sys_get_temp_dir(), 'eddsa_');
});

afterEach(function (): void {
    if (File::exists($this->tempKeyFile)) {
        File::delete($this->tempKeyFile);
    }
});

test('it generates eddsa key pair and returns it if write is null', function (): void {
    $config = $this->app->make(Repository::class);
    $logger = $this->app->make(LoggerInterface::class);
    $generator = new EdDSASignerKeyGenerator($config, $logger);

    $key = $generator->generate(null);
    expect($key)->toContain(PHP_EOL);

    $parts = explode(PHP_EOL, $key);
    expect(count($parts))->toBe(2)
        ->and(strlen($parts[0]))->toBe(64) // 32 bytes in hex
        ->and(strlen($parts[1]))->toBe(128); // 64 bytes in hex
});

test('it writes eddsa key pair to file', function (): void {
    $config = $this->app->make(Repository::class);
    $logger = $this->app->make(LoggerInterface::class);
    $generator = new EdDSASignerKeyGenerator($config, $logger);

    Config::set('crypto.signing.keys.eddsa', $this->tempKeyFile);

    $generator->generate('env_file_not_used_but_not_null');

    expect(File::exists($this->tempKeyFile))->toBeTrue();
    $content = File::get($this->tempKeyFile);
    $parts = explode(PHP_EOL, $content);
    expect(count($parts))->toBe(2);
});

test('it loads eddsa key pair from file', function (): void {
    $config = $this->app->make(Repository::class);
    $logger = $this->app->make(LoggerInterface::class);

    $keyPair = sodium_crypto_sign_keypair();
    $privateKey = bin2hex(sodium_crypto_sign_secretkey($keyPair));
    $publicKey = bin2hex(sodium_crypto_sign_publickey($keyPair));
    File::put($this->tempKeyFile, $publicKey.PHP_EOL.$privateKey);

    Config::set('crypto.signing.keys.eddsa', $this->tempKeyFile);

    $loader = EdDSASignerKeyLoader::make($config, $logger);

    [$loadedPublic, $loadedPrivate] = $loader->getKey();
    expect(bin2hex($loadedPublic))->toBe($publicKey)
        ->and(bin2hex($loadedPrivate))->toBe($privateKey);
});
