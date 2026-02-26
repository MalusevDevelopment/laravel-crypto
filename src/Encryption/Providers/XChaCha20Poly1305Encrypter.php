<?php

declare(strict_types=1);

namespace CodeLieutenant\LaravelCrypto\Encryption\Providers;

use CodeLieutenant\LaravelCrypto\Contracts\EncrypterProvider;
use Illuminate\Contracts\Encryption\DecryptException;
use SensitiveParameter;

final readonly class XChaCha20Poly1305Encrypter implements EncrypterProvider
{
    public function nonceSize(): int
    {
        return SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES;
    }

    public function tagSize(): int
    {
        return SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_ABYTES;
    }

    public function encrypt(#[SensitiveParameter] string $key, #[SensitiveParameter] mixed $value, string $nonce): string
    {
        return sodium_crypto_aead_xchacha20poly1305_ietf_encrypt((string) $value, '', $nonce, $key);
    }

    public function decrypt(#[SensitiveParameter] string $key, string $payload, string $nonce): mixed
    {
        $value = sodium_crypto_aead_xchacha20poly1305_ietf_decrypt($payload, '', $nonce, $key);

        throw_if($value === false, DecryptException::class, 'Payload cannot be decrypted');

        return $value;
    }

    public function encryptFile(#[SensitiveParameter] string $key, string $inputFilePath, string $outputFilePath): void
    {
        [$state, $header] = sodium_crypto_secretstream_xchacha20poly1305_init_push($key);

        $inputFile = fopen($inputFilePath, 'rb');
        $outputFile = fopen($outputFilePath, 'wb');

        try {
            if (!flock($outputFile, LOCK_EX)) {
                throw new \RuntimeException('Failed to acquire lock on output file');
            }
            if (fwrite($outputFile, $header) === false) {
                throw new \RuntimeException('Failed to write header to output file');
            }

            while (!feof($inputFile)) {
                $chunk = fread($inputFile, self::CHUNK_SIZE);
                if ($chunk === false) {
                    throw new \RuntimeException('Failed to read from input file');
                }
                if ($chunk === '') {
                    break;
                }
                $encryptedChunk = sodium_crypto_secretstream_xchacha20poly1305_push($state, $chunk);
                if (fwrite($outputFile, $encryptedChunk) === false) {
                    throw new \RuntimeException('Failed to write to output file');
                }
            }
            if (!fflush($outputFile)) {
                throw new \RuntimeException('Failed to flush output file');
            }
        } catch (\Throwable $e) {
            ftruncate($outputFile, 0);
            throw $e;
        } finally {
            sodium_memzero($state);
            flock($outputFile, LOCK_UN);
            fclose($inputFile);
            fclose($outputFile);
        }
    }

    public function decryptFile(#[SensitiveParameter] string $key, string $inputFilePath, string $outputFilePath): void
    {
        $inputFile = fopen($inputFilePath, 'rb');
        $outputFile = fopen($outputFilePath, 'wb');

        try {
            if (!flock($outputFile, LOCK_EX)) {
                throw new DecryptException('Failed to acquire lock on output file');
            }
            $header = fread($inputFile, SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_HEADERBYTES);

            if (strlen($header) !== SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_HEADERBYTES) {
                throw new DecryptException('Invalid header');
            }

            try {
                $state = sodium_crypto_secretstream_xchacha20poly1305_init_pull($header, $key);
            } catch (\SodiumException $e) {
                throw new DecryptException('Invalid header or key', 0, $e);
            }

            try {
                while (!feof($inputFile)) {
                    $chunk = fread($inputFile, self::CHUNK_SIZE + SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_ABYTES);
                    if ($chunk === false) {
                        throw new DecryptException('Failed to read from input file');
                    }
                    if ($chunk === '') {
                        break;
                    }

                    $decryptedChunk = sodium_crypto_secretstream_xchacha20poly1305_pull($state, $chunk);
                    if ($decryptedChunk === false) {
                        throw new DecryptException('Payload cannot be decrypted');
                    }

                    [$content, $tag] = $decryptedChunk;
                    if (fwrite($outputFile, $content) === false) {
                        throw new DecryptException('Failed to write to output file');
                    }
                }
                if (!fflush($outputFile)) {
                    throw new DecryptException('Failed to flush output file');
                }
            } finally {
                sodium_memzero($state);
            }
        } catch (\Throwable $e) {
            ftruncate($outputFile, 0);
            throw $e;
        } finally {
            flock($outputFile, LOCK_UN);
            fclose($inputFile);
            fclose($outputFile);
        }
    }

    public function encryptChunk(#[SensitiveParameter] string $key, string $chunk, string $nonce): string
    {
        return sodium_crypto_aead_xchacha20poly1305_ietf_encrypt($chunk, '', $nonce, $key);
    }

    public function decryptChunk(#[SensitiveParameter] string $key, string $chunk, string $nonce): string
    {
        $decrypted = sodium_crypto_aead_xchacha20poly1305_ietf_decrypt($chunk, '', $nonce, $key);

        if ($decrypted === false) {
            throw new DecryptException('Payload cannot be decrypted');
        }

        return $decrypted;
    }
}
