<?php

declare(strict_types=1);

use CodeLieutenant\LaravelCrypto\Encoder\PhpEncoder;
use CodeLieutenant\LaravelCrypto\Encryption\Encrypter;
use CodeLieutenant\LaravelCrypto\Encryption\Providers\AesGcm256Encrypter;
use CodeLieutenant\LaravelCrypto\Tests\InMemoryAppKeyKeyLoader;
use Illuminate\Contracts\Encryption\DecryptException;

test('decryption with previous keys works', function (): void {
    $currentKey = 'base64:'.base64_encode(random_bytes(32));
    $previousKey1 = 'base64:'.base64_encode(random_bytes(32));
    $previousKey2 = 'base64:'.base64_encode(random_bytes(32));

    // Encrypt something with $previousKey1
    $encrypterWithOldKey = new Encrypter(
        new InMemoryAppKeyKeyLoader($previousKey1),
        new PhpEncoder,
        null,
        new AesGcm256Encrypter
    );
    $payload1 = $encrypterWithOldKey->encryptString('old data 1');

    // Encrypt something with $previousKey2
    $encrypterWithOlderKey = new Encrypter(
        new InMemoryAppKeyKeyLoader($previousKey2),
        new PhpEncoder,
        null,
        new AesGcm256Encrypter
    );
    $payload2 = $encrypterWithOlderKey->encryptString('old data 2');

    // Create new encrypter with $currentKey and both old keys in previous keys
    $newEncrypter = new Encrypter(
        new InMemoryAppKeyKeyLoader($currentKey, [$previousKey1, $previousKey2]),
        new PhpEncoder,
        null,
        new AesGcm256Encrypter
    );

    expect($newEncrypter->decryptString($payload1))->toBe('old data 1')
        ->and($newEncrypter->decryptString($payload2))->toBe('old data 2');

    // Also verify it can decrypt its own payload
    $currentPayload = $newEncrypter->encryptString('current data');
    expect($newEncrypter->decryptString($currentPayload))->toBe('current data');
});

test('decryption fails if key is not in previous keys', function (): void {
    $currentKey = 'base64:'.base64_encode(random_bytes(32));
    $otherKey = 'base64:'.base64_encode(random_bytes(32));

    $encrypterWithOtherKey = new Encrypter(
        new InMemoryAppKeyKeyLoader($otherKey),
        new PhpEncoder,
        null,
        new AesGcm256Encrypter
    );
    $payload = $encrypterWithOtherKey->encryptString('other data');

    $newEncrypter = new Encrypter(
        new InMemoryAppKeyKeyLoader($currentKey, []),
        new PhpEncoder,
        null,
        new AesGcm256Encrypter
    );

    $newEncrypter->decryptString($payload);
})->throws(DecryptException::class);
