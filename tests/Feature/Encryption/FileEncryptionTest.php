<?php

declare(strict_types=1);

use CodeLieutenant\LaravelCrypto\Encoder\JsonEncoder;
use CodeLieutenant\LaravelCrypto\Encryption\Encrypter;
use CodeLieutenant\LaravelCrypto\Encryption\File\NativeFileEncrypter;
use CodeLieutenant\LaravelCrypto\Encryption\File\SecretStreamFileEncrypter;
use CodeLieutenant\LaravelCrypto\Encryption\Providers\Aegis128LGCMEncrypter;
use CodeLieutenant\LaravelCrypto\Encryption\Providers\Aegis256GCMEncrypter;
use CodeLieutenant\LaravelCrypto\Encryption\Providers\AesGcm256Encrypter;
use CodeLieutenant\LaravelCrypto\Encryption\Providers\OpenSSLEncrypter;
use CodeLieutenant\LaravelCrypto\Encryption\Providers\SecretBoxEncrypter;
use CodeLieutenant\LaravelCrypto\Encryption\Providers\XChaCha20Poly1305Encrypter;
use CodeLieutenant\LaravelCrypto\Contracts\EncrypterProvider;

it('should encrypt/decrypt files', function (string|EncrypterProvider $provider, int $keySize): void {
    if ($provider === AesGcm256Encrypter::class && !sodium_crypto_aead_aes256gcm_is_available()) {
        $this->markTestSkipped('AES-256-GCM is not supported on this platform.');
    }

    if ($provider === Aegis128LGCMEncrypter::class && !function_exists('sodium_crypto_aead_aegis128l_encrypt')) {
        $this->markTestSkipped('AEGIS-128L is not supported on this platform.');
    }

    if ($provider === Aegis256GCMEncrypter::class && !function_exists('sodium_crypto_aead_aegis256_encrypt')) {
        $this->markTestSkipped('AEGIS-256 is not supported on this platform.');
    }

    $providerInstance = is_string($provider) && !class_exists($provider)
        ? new OpenSSLEncrypter(app(CodeLieutenant\LaravelCrypto\Support\Random::class), $provider)
        : (is_string($provider) ? new $provider : $provider);

    $encryptor = new Encrypter(inMemoryKeyLoader($keySize), new JsonEncoder, null, $providerInstance, match ($provider) {
        XChaCha20Poly1305Encrypter::class => new SecretStreamFileEncrypter(),
        default => new NativeFileEncrypter($providerInstance),
    });

    $inputFile = tempnam(sys_get_temp_dir(), 'in');
    $encryptedFile = tempnam(sys_get_temp_dir(), 'enc');
    $decryptedFile = tempnam(sys_get_temp_dir(), 'dec');

    $content = 'Hello, this is a test file content. ' . str_repeat('A', 10000);
    file_put_contents($inputFile, $content);

    $encryptor->encryptFile($inputFile, $encryptedFile);
    expect(file_exists($encryptedFile))->toBeTrue()
        ->and(file_get_contents($encryptedFile))->not->toBe($content);

    $encryptor->decryptFile($encryptedFile, $decryptedFile);
    expect(file_exists($decryptedFile))->toBeTrue()
        ->and(file_get_contents($decryptedFile))->toBe($content);

    unlink($inputFile);
    unlink($encryptedFile);
    unlink($decryptedFile);
})->with([
    [XChaCha20Poly1305Encrypter::class, 32],
    [SecretBoxEncrypter::class, 32],
    [AesGcm256Encrypter::class, 32],
    [Aegis128LGCMEncrypter::class, 16],
    [Aegis256GCMEncrypter::class, 32],
    ['AES-256-GCM', 32],
    ['AES-256-CBC', 32],
    ['AES-128-GCM', 16],
    ['AES-128-CBC', 16],
]);

it('should handle empty files', function (string|EncrypterProvider $provider, int $keySize): void {
    if ($provider === AesGcm256Encrypter::class && !sodium_crypto_aead_aes256gcm_is_available()) {
        $this->markTestSkipped('AES-256-GCM is not supported on this platform.');
    }

    if ($provider === Aegis128LGCMEncrypter::class && !function_exists('sodium_crypto_aead_aegis128l_encrypt')) {
        $this->markTestSkipped('AEGIS-128L is not supported on this platform.');
    }

    if ($provider === Aegis256GCMEncrypter::class && !function_exists('sodium_crypto_aead_aegis256_encrypt')) {
        $this->markTestSkipped('AEGIS-256 is not supported on this platform.');
    }

    $providerInstance = is_string($provider) && !class_exists($provider)
        ? new OpenSSLEncrypter(app(CodeLieutenant\LaravelCrypto\Support\Random::class), $provider)
        : (is_string($provider) ? new $provider : $provider);

    $encryptor = new Encrypter(inMemoryKeyLoader($keySize), new JsonEncoder, null, $providerInstance, match ($provider) {
        XChaCha20Poly1305Encrypter::class => new SecretStreamFileEncrypter(),
        default => new NativeFileEncrypter($providerInstance),
    });

    $inputFile = tempnam(sys_get_temp_dir(), 'in_empty');
    $encryptedFile = tempnam(sys_get_temp_dir(), 'enc_empty');
    $decryptedFile = tempnam(sys_get_temp_dir(), 'dec_empty');

    file_put_contents($inputFile, '');

    $encryptor->encryptFile($inputFile, $encryptedFile);
    expect(file_exists($encryptedFile))->toBeTrue();

    $encryptor->decryptFile($encryptedFile, $decryptedFile);
    expect(file_exists($decryptedFile))->toBeTrue();
    expect(file_get_contents($decryptedFile))->toBe('');

    unlink($inputFile);
    unlink($encryptedFile);
    unlink($decryptedFile);
})->with([
    [XChaCha20Poly1305Encrypter::class, 32],
    [SecretBoxEncrypter::class, 32],
    [AesGcm256Encrypter::class, 32],
    [Aegis128LGCMEncrypter::class, 16],
    [Aegis256GCMEncrypter::class, 32],
    ['AES-256-GCM', 32],
    ['AES-256-CBC', 32],
    ['AES-128-GCM', 16],
    ['AES-128-CBC', 16],
]);

it('should throw DecryptException on corrupted file', function (string|EncrypterProvider $provider, int $keySize): void {
    if ($provider === AesGcm256Encrypter::class && !sodium_crypto_aead_aes256gcm_is_available()) {
        $this->markTestSkipped('AES-256-GCM is not supported on this platform.');
    }

    if ($provider === Aegis128LGCMEncrypter::class && !function_exists('sodium_crypto_aead_aegis128l_encrypt')) {
        $this->markTestSkipped('AEGIS-128L is not supported on this platform.');
    }

    if ($provider === Aegis256GCMEncrypter::class && !function_exists('sodium_crypto_aead_aegis256_encrypt')) {
        $this->markTestSkipped('AEGIS-256 is not supported on this platform.');
    }

    $providerInstance = is_string($provider) && !class_exists($provider)
        ? new OpenSSLEncrypter(app(CodeLieutenant\LaravelCrypto\Support\Random::class), $provider)
        : (is_string($provider) ? new $provider : $provider);

    $encryptor = new Encrypter(inMemoryKeyLoader($keySize), new JsonEncoder, null, $providerInstance, match ($provider) {
        XChaCha20Poly1305Encrypter::class => new SecretStreamFileEncrypter(),
        default => new NativeFileEncrypter($providerInstance),
    });

    $inputFile = tempnam(sys_get_temp_dir(), 'in_corr');
    $encryptedFile = tempnam(sys_get_temp_dir(), 'enc_corr');
    $decryptedFile = tempnam(sys_get_temp_dir(), 'dec_corr');

    file_put_contents($inputFile, 'Some data to encrypt');
    $encryptor->encryptFile($inputFile, $encryptedFile);

    // Corrupt the encrypted file
    $content = file_get_contents($encryptedFile);
    $content[strlen($content) - 10] = $content[strlen($content) - 10] ^ "\xFF";
    file_put_contents($encryptedFile, $content);

    expect(fn() => $encryptor->decryptFile($encryptedFile, $decryptedFile))
        ->toThrow(\Illuminate\Contracts\Encryption\DecryptException::class);

    unlink($inputFile);
    unlink($encryptedFile);
    unlink($decryptedFile);
})->with([
    [XChaCha20Poly1305Encrypter::class, 32],
    [SecretBoxEncrypter::class, 32],
    [AesGcm256Encrypter::class, 32],
    [Aegis128LGCMEncrypter::class, 16],
    [Aegis256GCMEncrypter::class, 32],
    ['AES-256-GCM', 32],
    ['AES-256-CBC', 32],
    ['AES-128-GCM', 16],
    ['AES-128-CBC', 16],
]);

it('should throw DecryptException on invalid header for XChaCha20Poly1305', function () {
    $encryptor = new Encrypter(inMemoryKeyLoader(32), new JsonEncoder, null, new XChaCha20Poly1305Encrypter, new SecretStreamFileEncrypter);

    $encryptedFile = tempnam(sys_get_temp_dir(), 'enc_header');
    $decryptedFile = tempnam(sys_get_temp_dir(), 'dec_header');

    file_put_contents($encryptedFile, str_repeat('A', 23)); // 1 byte too short

    expect(fn() => $encryptor->decryptFile($encryptedFile, $decryptedFile))
        ->toThrow(\Illuminate\Contracts\Encryption\DecryptException::class);

    unlink($encryptedFile);
    unlink($decryptedFile);
});

it('should throw DecryptException on invalid chunk for OpenSSL', function () {
    $encryptor = new Encrypter(inMemoryKeyLoader(32), new JsonEncoder, null, new OpenSSLEncrypter(app(CodeLieutenant\LaravelCrypto\Support\Random::class), 'AES-256-CBC'), new SecretStreamFileEncrypter);

    $encryptedFile = tempnam(sys_get_temp_dir(), 'enc_invalid');
    $decryptedFile = tempnam(sys_get_temp_dir(), 'dec_invalid');

    file_put_contents($encryptedFile, "This is not a valid laravel encrypted payload for a chunk");

    expect(fn() => $encryptor->decryptFile($encryptedFile, $decryptedFile))
        ->toThrow(\Illuminate\Contracts\Encryption\DecryptException::class);

    unlink($encryptedFile);
    unlink($decryptedFile);
});

it('should throw DecryptException on invalid key for XChaCha20Poly1305', function () {
    $encryptor = new Encrypter(inMemoryKeyLoader(32), new JsonEncoder, null, new XChaCha20Poly1305Encrypter, new SecretStreamFileEncrypter);

    $inputFile = tempnam(sys_get_temp_dir(), 'in_key');
    $encryptedFile = tempnam(sys_get_temp_dir(), 'enc_key');
    $decryptedFile = tempnam(sys_get_temp_dir(), 'dec_key');

    file_put_contents($inputFile, 'test');
    $encryptor->encryptFile($inputFile, $encryptedFile);

    // Use a different key for decryption
    $otherEncryptor = new Encrypter(inMemoryKeyLoader(32), new JsonEncoder, null, new XChaCha20Poly1305Encrypter, new SecretStreamFileEncrypter);

    expect(fn() => $otherEncryptor->decryptFile($encryptedFile, $decryptedFile))
        ->toThrow(\Illuminate\Contracts\Encryption\DecryptException::class);

    unlink($inputFile);
    unlink($encryptedFile);
    unlink($decryptedFile);
});

it('should throw DecryptException on corrupted chunk for XChaCha20Poly1305', function () {
    $encryptor = new Encrypter(inMemoryKeyLoader(32), new JsonEncoder, null, new XChaCha20Poly1305Encrypter, new SecretStreamFileEncrypter);

    $inputFile = tempnam(sys_get_temp_dir(), 'in_chunk');
    $encryptedFile = tempnam(sys_get_temp_dir(), 'enc_chunk');
    $decryptedFile = tempnam(sys_get_temp_dir(), 'dec_chunk');

    file_put_contents($inputFile, str_repeat('B', 100));
    $encryptor->encryptFile($inputFile, $encryptedFile);

    // Corrupt data after header
    $content = file_get_contents($encryptedFile);
    $content[30] = $content[30] ^ "\xFF";
    file_put_contents($encryptedFile, $content);

    expect(fn() => $encryptor->decryptFile($encryptedFile, $decryptedFile))
        ->toThrow(\Illuminate\Contracts\Encryption\DecryptException::class);

    unlink($inputFile);
    unlink($encryptedFile);
    unlink($decryptedFile);
});

it('should throw DecryptException on invalid nonce for other providers', function () {
    $encryptor = new Encrypter(inMemoryKeyLoader(32), new JsonEncoder, null, new AesGcm256Encrypter, new SecretStreamFileEncrypter);

    $encryptedFile = tempnam(sys_get_temp_dir(), 'enc_nonce');
    $decryptedFile = tempnam(sys_get_temp_dir(), 'dec_nonce');

    file_put_contents($encryptedFile, str_repeat('A', 11)); // 1 byte too short for AES-GCM (12 bytes)

    expect(fn() => $encryptor->decryptFile($encryptedFile, $decryptedFile))
        ->toThrow(\Illuminate\Contracts\Encryption\DecryptException::class);

    unlink($encryptedFile);
    unlink($decryptedFile);
});
