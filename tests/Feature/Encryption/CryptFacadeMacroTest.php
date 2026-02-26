<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\Crypt;

test('Crypt facade has encryptFile and decryptFile macros', function () {
    expect(Crypt::hasMacro('encryptFile'))->toBeTrue()
        ->and(Crypt::hasMacro('decryptFile'))->toBeTrue();
});

test('Crypt::encryptFile and Crypt::decryptFile work', function (string $cipher) {
    if (str_starts_with($cipher, 'Sodium_')) {
        $keySize = match ($cipher) {
            'Sodium_AES256GCM', 'Sodium_XChaCha20Poly1305', 'Sodium_AEGIS256GCM' => 32,
            'Sodium_AEGIS128LGCM' => 16,
            default => 32,
        };

        // Ensure we have a valid key for the cipher
        Config::set('app.key', 'base64:'.base64_encode(random_bytes($keySize)));
    }

    Config::set('app.cipher', $cipher);

    $inputFile = tempnam(sys_get_temp_dir(), 'in_macro');
    $encryptedFile = tempnam(sys_get_temp_dir(), 'enc_macro');
    $decryptedFile = tempnam(sys_get_temp_dir(), 'dec_macro');

    $content = 'Hello from Crypt facade macro!';
    file_put_contents($inputFile, $content);

    Crypt::encryptFile($inputFile, $encryptedFile);
    expect(file_exists($encryptedFile))->toBeTrue()
        ->and(file_get_contents($encryptedFile))->not->toBe($content);

    Crypt::decryptFile($encryptedFile, $decryptedFile);
    expect(file_exists($decryptedFile))->toBeTrue()
        ->and(file_get_contents($decryptedFile))->toBe($content);

    unlink($inputFile);
    unlink($encryptedFile);
    unlink($decryptedFile);
})->with([
    'AES-256-CBC',
    'Sodium_XChaCha20Poly1305',
]);

test('Crypt macros throw EncryptException/DecryptException on failure', function () {
    Config::set('app.cipher', 'AES-256-CBC');
    Config::set('app.key', 'base64:'.base64_encode(random_bytes(32)));

    $invalidFile = '/path/to/nonexistent/file';
    $outputFile = tempnam(sys_get_temp_dir(), 'out');

    expect(fn () => Crypt::encryptFile($invalidFile, $outputFile))
        ->toThrow(\Illuminate\Contracts\Encryption\EncryptException::class);

    $corruptedFile = tempnam(sys_get_temp_dir(), 'corr');
    file_put_contents($corruptedFile, 'corrupted content');

    expect(fn () => Crypt::decryptFile($corruptedFile, $outputFile))
        ->toThrow(\Illuminate\Contracts\Encryption\DecryptException::class);

    unlink($outputFile);
    unlink($corruptedFile);
});
