<?php

declare(strict_types=1);

namespace CodeLieutenant\LaravelCrypto\Benchmarks;

use CodeLieutenant\LaravelCrypto\Encoder\IgbinaryEncoder;
use CodeLieutenant\LaravelCrypto\Encoder\JsonEncoder;
use CodeLieutenant\LaravelCrypto\Encoder\PhpEncoder;
use CodeLieutenant\LaravelCrypto\Encryption\AesGcm256Encrypter;
use CodeLieutenant\LaravelCrypto\Encryption\XChaCha20Poly1305Encrypter;
use CodeLieutenant\LaravelCrypto\Support\Random;
use Generator;
use Illuminate\Encryption\Encrypter;
use Monolog\Logger;
use PhpBench\Attributes\ParamProviders;

class EncryptionBench
{
    #[ParamProviders('provideLaravelEncryption')]
    public function benchLaravelEncryptionWithoutSerialization(array $params): void
    {
        $data = $params['data'];
        /** @var Encrypter $encrypter */
        $encrypter = $params['encrypter'];

        $value = $encrypter->encryptString($data);
    }

    #[ParamProviders('provideLaravelEncryption')]
    public function benchLaravelEncryptionWithSerialization(array $params): void
    {
        /** @var array $data */
        $data = $params['data'];
        /** @var Encrypter $encrypter */
        $encrypter = $params['encrypter'];

        $value = $encrypter->encrypt($data);
    }

    public function providerChaCha20Crypto(): Generator
    {
        $logger = new Logger('benchmark');

        $encoders = [
            'PHP' => new PhpEncoder,
            'JSON' => new JsonEncoder,
            'IGBINARY' => new IgbinaryEncoder,
        ];

        $data = [
            '32' => Random::bytes(32), // 32B
            '128' => Random::bytes(128), // 128B
            '256' => Random::bytes(256), // 256B
            '1KiB' => Random::bytes(1024), // 1KB
            '32KiB' => Random::bytes(32 * 1024), // 32KB
            '1MiB' => Random::bytes(1024 * 1024), // 1MB
        ];

        foreach ($data as $dataName => $dataValue) {
            foreach ($encoders as $encoderName => $encoder) {
                yield 'ChaCha20-'.$encoderName.'-'.$dataName => [
                    'data' => $dataValue,
                    'encrypter' => new XChaCha20Poly1305Encrypter(new KeyKeyLoader(Random::bytes(32)), $logger, $encoder),
                ];
            }
        }
    }

    public function providerAESGCMCrypto(): Generator
    {
        $logger = new Logger('benchmark');

        $encoders = [
            'PHP' => new PhpEncoder,
            'JSON' => new JsonEncoder,
            'IGBINARY' => new IgbinaryEncoder,
        ];

        $data = [
            '32' => Random::bytes(32), // 32B
            '128' => Random::bytes(128), // 128B
            '256' => Random::bytes(256), // 256B
            '1KiB' => Random::bytes(1024), // 1KB
            '32KiB' => Random::bytes(32 * 1024), // 32KB
            '1MiB' => Random::bytes(1024 * 1024), // 1MB
        ];

        foreach ($data as $dataName => $dataValue) {
            foreach ($encoders as $encoderName => $encoder) {
                yield 'ChaCha20-'.$encoderName.'-'.$dataName => [
                    'data' => $dataValue,
                    'encrypter' => new AesGcm256Encrypter(new KeyKeyLoader(Random::bytes(32)), $logger, $encoder),
                ];
            }
        }
    }

    public function provideLaravelEncryption(): Generator
    {
        $data = [
            '32' => Random::bytes(32), // 32B
            '128' => Random::bytes(128), // 128B
            '256' => Random::bytes(256), // 256B
            '1KiB' => Random::bytes(1024), // 1KB
            '32KiB' => Random::bytes(32 * 1024), // 32KB
            '1MiB' => Random::bytes(1024 * 1024), // 1MB
        ];

        $encrypters = [
            'AES-256-CBC' => new Encrypter(Random::bytes(32), 'AES-256-CBC'),
            'AES-128-CBC' => new Encrypter(Random::bytes(32), 'AES-128-CBC'),
            'AES-256-GCM' => new Encrypter(Random::bytes(32), 'AES-256-GCM'),
            'AES-128-GCM' => new Encrypter(Random::bytes(32), 'AES-128-GCM'),
        ];

        foreach ($data as $dataName => $dataValue) {
            foreach ($encrypters as $encrypterName => $encrypter) {
                yield 'Laravel-'.$encrypterName.'-'.$dataName => [
                    'data' => $dataValue,
                    'encrypter' => $encrypter,
                ];
            }
        }
    }
    //
    //    public function benchXChaCha20Poly1305(): void
    //    {
    //        $this->xchacha->encryptString($this->data);
    //    }
    //
    //    public function benchAes256gcm(): void
    //    {
    //        $this->aes256gcm->encryptString($this->data);
    //    }
}
