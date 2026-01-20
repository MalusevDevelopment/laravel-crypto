<?php

declare(strict_types=1);

use CodeLieutenant\LaravelCrypto\Encoder\JsonEncoder;
use CodeLieutenant\LaravelCrypto\Encryption\Encrypter;
use CodeLieutenant\LaravelCrypto\Encryption\Providers\Aegis128LGCMEncrypter;

beforeEach(function (): void {
    if (! function_exists('sodium_crypto_aead_aegis128l_encrypt')) {
        $this->markTestSkipped('AEGIS-128L is not available');
    }
});

it('should encrypt/decrypt data', function (bool $serialize): void {
    $encryptor = new Encrypter(inMemoryKeyLoader(16), new JsonEncoder, null, new Aegis128LGCMEncrypter);
    $data = $serialize ? ['data'] : 'hello world';
    $encrypted = $encryptor->encrypt($data, $serialize);

    expect($encrypted)
        ->toBeString()
        ->and($encryptor->decrypt($encrypted, $serialize))
        ->toBe($data);
})->with([true, false]);

it('should encrypt/decrypt string', function (): void {
    $encryptor = new Encrypter(inMemoryKeyLoader(16), new JsonEncoder, null, new Aegis128LGCMEncrypter);
    $data = 'hello world';
    $encrypted = $encryptor->encryptString($data);

    expect($encrypted)
        ->toBeString()
        ->and($encryptor->decryptString($encrypted))
        ->toBe($data);
});
