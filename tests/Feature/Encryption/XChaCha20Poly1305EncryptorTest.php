<?php

declare(strict_types=1);

use CodeLieutenant\LaravelCrypto\Encoder\JsonEncoder;
use CodeLieutenant\LaravelCrypto\Encryption\Encrypter;
use CodeLieutenant\LaravelCrypto\Encryption\Providers\XChaCha20Poly1305Encrypter;

it('should encrypt/decrypt data', function (bool $serialize): void {
    $encryptor = new Encrypter(inMemoryKeyLoader(), new JsonEncoder, null, new XChaCha20Poly1305Encrypter);
    $data = $serialize ? ['data'] : 'hello world';
    $encrypted = $encryptor->encrypt($data, $serialize);

    expect($encrypted)
        ->toBeString()
        ->and($encryptor->decrypt($encrypted, $serialize))
        ->toBe($data);
})->with([true, false]);

it('should encrypt/decrypt string', function (): void {
    $encryptor = new Encrypter(inMemoryKeyLoader(), new JsonEncoder, null, new XChaCha20Poly1305Encrypter);
    $data = 'hello world';
    $encrypted = $encryptor->encryptString($data);

    expect($encrypted)
        ->toBeString()
        ->and($encryptor->decryptString($encrypted))
        ->toBe($data);
});
