<?php

declare(strict_types=1);

namespace CodeLieutenant\LaravelCrypto\Benchmarks;

use CodeLieutenant\LaravelCrypto\Encryption\AesGcm256Encrypter;
use CodeLieutenant\LaravelCrypto\Encryption\XChaCha20Poly1305Encrypter;
use Illuminate\Encryption\Encrypter;

class DecryptionBench
{
    private Encrypter $laravelEncrypter;

    private XChaCha20Poly1305Encrypter $xchacha;

    private AesGcm256Encrypter $aes256gcm;

    private string $xChaChaData;

    private string $aes256GcmData;

    private string $laravelData;

    public function __construct()
    {
        $key = base64_decode(file_get_contents(__DIR__.'/key'));
        $this->laravelEncrypter = new Encrypter($key, 'AES-256-CBC');
        $this->xchacha = new XChaCha20Poly1305Encrypter($key);
        $this->aes256gcm = new AesGcm256Encrypter($key);
        $this->xChaChaData = file_get_contents(__DIR__.'/encrypted-xchacha');
        $this->laravelData = file_get_contents(__DIR__.'/encrypted-laravel');
        $this->aes256GcmData = file_get_contents(__DIR__.'/encrypted-aes256gcm');
    }

    public function benchLaravelDecryption(): void
    {
        $this->laravelEncrypter->decryptString($this->laravelData);
    }

    public function benchXChaCha20Poly1305Decryption(): void
    {
        $this->xchacha->decryptString($this->xChaChaData);
    }

    public function benchAes256gcmDecryption(): void
    {
        $this->aes256gcm->decryptString($this->aes256GcmData);
    }
}
