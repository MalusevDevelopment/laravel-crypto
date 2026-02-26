<?php

declare(strict_types=1);

namespace Tests\Feature\Encryption;

use CodeLieutenant\LaravelCrypto\Encryption\Encrypter;
use CodeLieutenant\LaravelCrypto\Keys\Loaders\FileKeyLoader;
use CodeLieutenant\LaravelCrypto\Tests\InMemoryAppKeyKeyLoader;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\Crypt;

test('it falls back to app key if file encryption key is not set', function () {
    $appKey = 'base64:'.base64_encode(random_bytes(32));
    Config::set('app.key', $appKey);
    Config::set('crypto.file_encryption.key', null);

    $loader = FileKeyLoader::make(app(\Illuminate\Contracts\Config\Repository::class));
    expect(base64_encode($loader->getKey()))->toBe(substr($appKey, 7));
});

test('it uses custom file encryption key if set', function () {
    $appKey = 'base64:'.base64_encode(random_bytes(32));
    $fileKey = 'base64:'.base64_encode(random_bytes(32));
    Config::set('app.key', $appKey);
    Config::set('crypto.file_encryption.key', $fileKey);

    $loader = FileKeyLoader::make(app(\Illuminate\Contracts\Config\Repository::class));
    expect(base64_encode($loader->getKey()))->toBe(substr($fileKey, 7));
    expect(base64_encode($loader->getKey()))->not->toBe(substr($appKey, 7));
});

test('it has the correct file keys', function () {
    $oldKey = 'base64:'.base64_encode(random_bytes(32));
    $currentKey = 'base64:'.base64_encode(random_bytes(32));

    Config::set('app.key', $currentKey);
    Config::set('crypto.file_encryption.key', $currentKey);
    Config::set('crypto.file_encryption.previous_keys', $oldKey);

    app()->forgetInstance(\CodeLieutenant\LaravelCrypto\Encryption\Encrypter::class);
    app()->forgetInstance('encrypter');
    app()->forgetInstance(\CodeLieutenant\LaravelCrypto\Keys\Loaders\FileKeyLoader::class);

    /** @var Encrypter $encrypter */
    $encrypter = app('encrypter');

    expect(base64_encode($encrypter->getFileKey()))->toBe(substr($currentKey, 7));
    $previous = $encrypter->getPreviousFileKeys();
    expect($previous)->toHaveCount(1);
    expect(base64_encode($previous[0]))->toBe(substr($oldKey, 7));
});

test('it can decrypt files with previous keys', function () {
    $oldKey = 'base64:'.base64_encode(random_bytes(32));
    $currentKey = 'base64:'.base64_encode(random_bytes(32));

    Config::set('app.key', $currentKey);
    Config::set('app.cipher', 'Sodium_XChaCha20Poly1305');
    Config::set('app.previous_keys', $oldKey);
    Config::set('crypto.file_encryption.key', null);
    Config::set('crypto.file_encryption.previous_keys', null);

    Crypt::clearResolvedInstances();
    app()->forgetInstance('encrypter');
    app()->forgetInstance(\CodeLieutenant\LaravelCrypto\Encryption\Encrypter::class);
    app()->forgetInstance(\CodeLieutenant\LaravelCrypto\Keys\Loaders\FileKeyLoader::class);
    app()->forgetInstance(\CodeLieutenant\LaravelCrypto\Keys\Loaders\AppKeyLoader::class);

    $libEncrypter = app('encrypter');

    $inputFile = tempnam(sys_get_temp_dir(), 'in');
    $encryptedFile = tempnam(sys_get_temp_dir(), 'enc');
    $decryptedFile = tempnam(sys_get_temp_dir(), 'dec');

    $content = 'Secret content '.str_repeat('A', 1000);
    file_put_contents($inputFile, $content);

    // Encrypt with old key by manually creating an encrypter
    $oldKeyLoader = new InMemoryAppKeyKeyLoader($oldKey);
    $manualEncrypter = new Encrypter(
        $oldKeyLoader,
        app(\CodeLieutenant\LaravelCrypto\Contracts\Encoder::class),
        null,
        new \CodeLieutenant\LaravelCrypto\Encryption\Providers\XChaCha20Poly1305Encrypter,
        new \CodeLieutenant\LaravelCrypto\Encryption\File\SecretStreamFileEncrypter
    );

    $manualEncrypter->encryptFile($inputFile, $encryptedFile);

    // Now try to decrypt using the Facade which should use the current key and then the old key
    Crypt::decryptFile($encryptedFile, $decryptedFile);

    expect(file_get_contents($decryptedFile))->toBe($content);

    unlink($inputFile);
    unlink($encryptedFile);
    unlink($decryptedFile);
});
