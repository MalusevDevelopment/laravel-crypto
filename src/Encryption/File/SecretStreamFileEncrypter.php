<?php

declare(strict_types=1);

namespace CodeLieutenant\LaravelCrypto\Encryption\File;

use CodeLieutenant\LaravelCrypto\Contracts\EncrypterProvider;
use CodeLieutenant\LaravelCrypto\Contracts\FileEncrypter;
use Illuminate\Contracts\Encryption\DecryptException;
use Illuminate\Contracts\Encryption\EncryptException;
use SensitiveParameter;
use SodiumException;
use Throwable;

final readonly class SecretStreamFileEncrypter implements FileEncrypter
{
    public function encryptFile(#[SensitiveParameter] string $key, string $inputFilePath, string $outputFilePath): void
    {
        [$state, $header] = sodium_crypto_secretstream_xchacha20poly1305_init_push($key);

        $inputFile = fopen($inputFilePath, 'rb');
        $outputFile = fopen($outputFilePath, 'wb');

        try {
            if (!flock($outputFile, LOCK_EX)) {
                throw new EncryptException('Failed to acquire lock on output file');
            }
            if (fwrite($outputFile, $header) === false) {
                throw new EncryptException('Failed to write header to output file');
            }

            while (!feof($inputFile)) {
                $chunk = fread($inputFile, EncrypterProvider::CHUNK_SIZE);
                if ($chunk === false) {
                    throw new EncryptException('Failed to read from input file');
                }

                $tag = feof($inputFile) ? SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_FINAL : SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_MESSAGE;

                if ($chunk === '' && $tag !== SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_FINAL) {
                    break;
                }

                $encryptedChunk = sodium_crypto_secretstream_xchacha20poly1305_push($state, $chunk, '', $tag);
                if (fwrite($outputFile, $encryptedChunk) === false) {
                    throw new EncryptException('Failed to write to output file');
                }
            }
            if (!fflush($outputFile)) {
                throw new EncryptException('Failed to flush output file');
            }
        } catch (Throwable $e) {
            ftruncate($outputFile, 0);
            throw new EncryptException('Failed to encrypt the file', previous: $e);
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

            if (mb_strlen($header, '8bit') !== SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_HEADERBYTES) {
                throw new DecryptException('Invalid header');
            }

            try {
                $state = sodium_crypto_secretstream_xchacha20poly1305_init_pull($header, $key);
            } catch (SodiumException $e) {
                throw new DecryptException('Invalid header or key', 0, $e);
            }

            try {
                while (!feof($inputFile)) {
                    $chunk = fread($inputFile, EncrypterProvider::CHUNK_SIZE + SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_ABYTES);
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

                    $eof = feof($inputFile);
                    if ($tag === SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_FINAL) {
                        if (!$eof) {
                            // Check if there is anything else in the file.
                            // fread might have reached EOF, but feof only returns true after a read PAST EOF.
                            // But here we might have more data.
                            $remainder = fread($inputFile, 1);
                            if ($remainder !== '' && $remainder !== false) {
                                throw new DecryptException('End of stream reached before the end of the file');
                            }
                        }
                    } elseif ($eof) {
                        throw new DecryptException('End of file reached before the end of the stream');
                    }

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
        } catch (Throwable $e) {
            ftruncate($outputFile, 0);
            throw new DecryptException('Failed to decrypt the file', previous: $e);
        } finally {
            flock($outputFile, LOCK_UN);
            fclose($inputFile);
            fclose($outputFile);
        }
    }
}
