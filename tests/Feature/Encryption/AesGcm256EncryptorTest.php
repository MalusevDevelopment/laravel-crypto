<?php

declare(strict_types=1);

use CodeLieutenant\LaravelCrypto\Encryption\AesGcm256Encrypter;

it('should encrypt/decrypt data', function (bool $serialize): void {
    $encryptor = new AesGcm256Encrypter(inMemoryKeyLoader());
    $data = $serialize ? ['data'] : 'hello world';
    $encrypted = $encryptor->encrypt($data, $serialize);

    expect($encrypted)
        ->toBeString()
        ->and($encryptor->decrypt($encrypted, $serialize))
        ->toBe($data);
})->with([true, false]);

it('should encrypt/decrypt string', function (): void {
    $encryptor = new AesGcm256Encrypter(inMemoryKeyLoader());
    $data = 'hello world';
    $encrypted = $encryptor->encryptString($data);

    expect($encrypted)
        ->toBeString()
        ->and($encryptor->decryptString($encrypted))
        ->toBe($data);
});
