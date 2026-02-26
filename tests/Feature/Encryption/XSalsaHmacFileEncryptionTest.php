<?php

declare(strict_types=1);

use CodeLieutenant\LaravelCrypto\Encoder\JsonEncoder;
use CodeLieutenant\LaravelCrypto\Encryption\Encrypter;
use CodeLieutenant\LaravelCrypto\Encryption\File\XSalsaHmacFileEncrypter;
use CodeLieutenant\LaravelCrypto\Encryption\Providers\XChaCha20Poly1305Encrypter;

it('should encrypt/decrypt files using XSalsaHmac', function (): void {
    $encryptor = new Encrypter(inMemoryKeyLoader(32), new JsonEncoder, null, new XChaCha20Poly1305Encrypter, new XSalsaHmacFileEncrypter);

    $inputFile = tempnam(sys_get_temp_dir(), 'in_xsalsa');
    $encryptedFile = tempnam(sys_get_temp_dir(), 'enc_xsalsa');
    $decryptedFile = tempnam(sys_get_temp_dir(), 'dec_xsalsa');

    $content = 'Hello, this is a test file content for XSalsaHmac. '.str_repeat('B', 10000);
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
});

it('should handle empty files using XSalsaHmac', function (): void {
    $encryptor = new Encrypter(inMemoryKeyLoader(32), new JsonEncoder, null, new XChaCha20Poly1305Encrypter, new XSalsaHmacFileEncrypter);

    $inputFile = tempnam(sys_get_temp_dir(), 'in_xsalsa_empty');
    $encryptedFile = tempnam(sys_get_temp_dir(), 'enc_xsalsa_empty');
    $decryptedFile = tempnam(sys_get_temp_dir(), 'dec_xsalsa_empty');

    file_put_contents($inputFile, '');

    $encryptor->encryptFile($inputFile, $encryptedFile);
    expect(file_exists($encryptedFile))->toBeTrue();

    $encryptor->decryptFile($encryptedFile, $decryptedFile);
    expect(file_exists($decryptedFile))->toBeTrue();
    expect(file_get_contents($decryptedFile))->toBe('');

    unlink($inputFile);
    unlink($encryptedFile);
    unlink($decryptedFile);
});

it('should throw DecryptException on corrupted file using XSalsaHmac', function (): void {
    $encryptor = new Encrypter(inMemoryKeyLoader(32), new JsonEncoder, null, new XChaCha20Poly1305Encrypter, new XSalsaHmacFileEncrypter);

    $inputFile = tempnam(sys_get_temp_dir(), 'in_xsalsa_corr');
    $encryptedFile = tempnam(sys_get_temp_dir(), 'enc_xsalsa_corr');
    $decryptedFile = tempnam(sys_get_temp_dir(), 'dec_xsalsa_corr');

    file_put_contents($inputFile, 'Some data to encrypt');
    $encryptor->encryptFile($inputFile, $encryptedFile);

    // Corrupt the encrypted file
    $content = file_get_contents($encryptedFile);
    $content[strlen($content) - 10] = $content[strlen($content) - 10] ^ "\xFF";
    file_put_contents($encryptedFile, $content);

    expect(fn () => $encryptor->decryptFile($encryptedFile, $decryptedFile))
        ->toThrow(\Illuminate\Contracts\Encryption\DecryptException::class);

    unlink($inputFile);
    unlink($encryptedFile);
    unlink($decryptedFile);
});

it('should throw DecryptException on invalid header for XSalsaHmac', function () {
    $encryptor = new Encrypter(inMemoryKeyLoader(32), new JsonEncoder, null, new XChaCha20Poly1305Encrypter, new XSalsaHmacFileEncrypter);

    $encryptedFile = tempnam(sys_get_temp_dir(), 'enc_xsalsa_header');
    $decryptedFile = tempnam(sys_get_temp_dir(), 'dec_xsalsa_header');

    file_put_contents($encryptedFile, str_repeat('A', 23)); // 1 byte too short (nonce is 24)

    expect(fn () => $encryptor->decryptFile($encryptedFile, $decryptedFile))
        ->toThrow(\Illuminate\Contracts\Encryption\DecryptException::class);

    unlink($encryptedFile);
    unlink($decryptedFile);
});

it('should throw DecryptException on invalid key for XSalsaHmac', function () {
    $encryptor = new Encrypter(inMemoryKeyLoader(32), new JsonEncoder, null, new XChaCha20Poly1305Encrypter, new XSalsaHmacFileEncrypter);

    $inputFile = tempnam(sys_get_temp_dir(), 'in_xsalsa_key');
    $encryptedFile = tempnam(sys_get_temp_dir(), 'enc_xsalsa_key');
    $decryptedFile = tempnam(sys_get_temp_dir(), 'dec_xsalsa_key');

    file_put_contents($inputFile, 'test');
    $encryptor->encryptFile($inputFile, $encryptedFile);

    // Use a different key for decryption
    $otherEncryptor = new Encrypter(inMemoryKeyLoader(32), new JsonEncoder, null, new XChaCha20Poly1305Encrypter, new XSalsaHmacFileEncrypter);

    expect(fn () => $otherEncryptor->decryptFile($encryptedFile, $decryptedFile))
        ->toThrow(\Illuminate\Contracts\Encryption\DecryptException::class);

    unlink($inputFile);
    unlink($encryptedFile);
    unlink($decryptedFile);
});
