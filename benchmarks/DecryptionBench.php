<?php

declare(strict_types=1);

namespace CodeLieutenant\LaravelCrypto\Benchmarks;

use CodeLieutenant\LaravelCrypto\Encoder\JsonEncoder;
use CodeLieutenant\LaravelCrypto\Encryption\Encrypter as LibEncrypter;
use CodeLieutenant\LaravelCrypto\Encryption\Providers\Aegis128LGCMEncrypter;
use CodeLieutenant\LaravelCrypto\Encryption\Providers\Aegis256GCMEncrypter;
use CodeLieutenant\LaravelCrypto\Encryption\Providers\AesGcm256Encrypter;
use CodeLieutenant\LaravelCrypto\Encryption\Providers\XChaCha20Poly1305Encrypter;
use Generator;
use Illuminate\Encryption\Encrypter as LaravelEncrypter;
use PhpBench\Attributes\Iterations;
use PhpBench\Attributes\ParamProviders;
use PhpBench\Attributes\Revs;

class DecryptionBench
{
    #[ParamProviders('provideEncrypters')]
    #[Revs(1000)]
    #[Iterations(5)]
    public function benchDecryption(array $params): void
    {
        $params['encrypter']->decryptString($params['payload']);
    }

    public function provideEncrypters(): Generator
    {
        $data = [
            '1KiB' => random_bytes(1024),
            '32KiB' => random_bytes(32 * 1024),
            '1MiB' => random_bytes(1024 * 1024),
        ];

        $key32 = random_bytes(32);
        $key16 = random_bytes(16);

        $encrypters = [
            'Laravel AES-256-CBC' => new LaravelEncrypter($key32, 'AES-256-CBC'),
            'Laravel AES-256-GCM' => new LaravelEncrypter($key32, 'AES-256-GCM'),
            'Sodium AES-256-GCM' => new LibEncrypter(new KeyLoader($key32), new JsonEncoder, null, new AesGcm256Encrypter),
            'Sodium XChaCha20-Poly1305' => new LibEncrypter(new KeyLoader($key32), new JsonEncoder, null, new XChaCha20Poly1305Encrypter),
            'Sodium AEGIS-128L' => new LibEncrypter(new KeyLoader($key16), new JsonEncoder, null, new Aegis128LGCMEncrypter),
            'Sodium AEGIS-256' => new LibEncrypter(new KeyLoader($key32), new JsonEncoder, null, new Aegis256GCMEncrypter),
        ];

        foreach ($data as $dataName => $dataValue) {
            foreach ($encrypters as $encrypterName => $encrypter) {
                yield "{$encrypterName}-{$dataName}" => [
                    'payload' => $encrypter->encryptString($dataValue),
                    'encrypter' => $encrypter,
                ];
            }
        }
    }
}
