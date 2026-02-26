<?php

declare(strict_types=1);

namespace CodeLieutenant\LaravelCrypto\Encryption\File;

use CodeLieutenant\LaravelCrypto\Contracts\EncrypterProvider;
use CodeLieutenant\LaravelCrypto\Contracts\FileEncrypter;
use Illuminate\Contracts\Encryption\DecryptException;
use Illuminate\Contracts\Encryption\EncryptException;
use SensitiveParameter;
use Throwable;

final readonly class XSalsaHmacFileEncrypter implements FileEncrypter
{
    private const string KDF_CONTEXT = 'XSalsaHm';

    private const int TAG_MESSAGE = 0x00;

    private const int TAG_FINAL = 0x01;

    public function encryptFile(#[SensitiveParameter] string $key, string $inputFilePath, string $outputFilePath): void
    {
        $nonce = random_bytes(SODIUM_CRYPTO_STREAM_NONCEBYTES);
        $encKey = sodium_crypto_kdf_derive_from_key(SODIUM_CRYPTO_STREAM_KEYBYTES, 1, self::KDF_CONTEXT, $key);
        $authKey = sodium_crypto_kdf_derive_from_key(SODIUM_CRYPTO_AUTH_KEYBYTES, 2, self::KDF_CONTEXT, $key);

        $inputFile = fopen($inputFilePath, 'rb');
        $outputFile = fopen($outputFilePath, 'wb');

        try {
            if (! flock($outputFile, LOCK_EX)) {
                throw new EncryptException('Failed to acquire lock on output file');
            }
            if (fwrite($outputFile, $nonce) === false) {
                throw new EncryptException('Failed to write nonce to output file');
            }

            while (! feof($inputFile)) {
                $chunk = fread($inputFile, EncrypterProvider::CHUNK_SIZE);
                if ($chunk === false) {
                    throw new EncryptException('Failed to read from input file');
                }

                $isFinal = feof($inputFile);
                if ($chunk === '' && ! $isFinal) {
                    break;
                }

                $tag = $isFinal ? self::TAG_FINAL : self::TAG_MESSAGE;

                $encryptedChunk = sodium_crypto_stream_xor($chunk, $nonce, $encKey);
                $mac = sodium_crypto_auth(pack('C', $tag).$nonce.$encryptedChunk, $authKey);

                if (fwrite($outputFile, $mac.$encryptedChunk) === false) {
                    throw new EncryptException('Failed to write to output file');
                }

                sodium_increment($nonce);
            }

            if (! fflush($outputFile)) {
                throw new EncryptException('Failed to flush output file');
            }
        } catch (Throwable $e) {
            ftruncate($outputFile, 0);
            throw new EncryptException('Failed to encrypt the file', previous: $e);
        } finally {
            sodium_memzero($encKey);
            sodium_memzero($authKey);
            flock($outputFile, LOCK_UN);
            fclose($inputFile);
            fclose($outputFile);
        }
    }

    public function decryptFile(#[SensitiveParameter] string $key, string $inputFilePath, string $outputFilePath): void
    {
        $encKey = sodium_crypto_kdf_derive_from_key(SODIUM_CRYPTO_STREAM_KEYBYTES, 1, self::KDF_CONTEXT, $key);
        $authKey = sodium_crypto_kdf_derive_from_key(SODIUM_CRYPTO_AUTH_KEYBYTES, 2, self::KDF_CONTEXT, $key);

        $inputFile = fopen($inputFilePath, 'rb');
        $outputFile = fopen($outputFilePath, 'wb');

        try {
            if (! flock($outputFile, LOCK_EX)) {
                throw new DecryptException('Failed to acquire lock on output file');
            }

            $nonce = fread($inputFile, SODIUM_CRYPTO_STREAM_NONCEBYTES);
            if (mb_strlen($nonce, '8bit') !== SODIUM_CRYPTO_STREAM_NONCEBYTES) {
                throw new DecryptException('Invalid header');
            }

            while (! feof($inputFile)) {
                $chunkWithMac = fread($inputFile, EncrypterProvider::CHUNK_SIZE + SODIUM_CRYPTO_AUTH_BYTES);
                if ($chunkWithMac === false) {
                    throw new DecryptException('Failed to read from input file');
                }
                if ($chunkWithMac === '') {
                    break;
                }

                if (strlen($chunkWithMac) < SODIUM_CRYPTO_AUTH_BYTES) {
                    throw new DecryptException('Corrupted chunk');
                }

                $mac = substr($chunkWithMac, 0, SODIUM_CRYPTO_AUTH_BYTES);
                $encryptedChunk = substr($chunkWithMac, SODIUM_CRYPTO_AUTH_BYTES);

                $eof = feof($inputFile);
                $tag = $eof ? self::TAG_FINAL : self::TAG_MESSAGE;

                if (! sodium_crypto_auth_verify($mac, pack('C', $tag).$nonce.$encryptedChunk, $authKey)) {
                    // Handle the case where feof was false but we are at the end
                    if (! $eof) {
                        $remainder = fread($inputFile, 1);
                        if ($remainder === '' || $remainder === false) {
                            $tag = self::TAG_FINAL;
                            if (! sodium_crypto_auth_verify($mac, pack('C', $tag).$nonce.$encryptedChunk, $authKey)) {
                                throw new DecryptException('Payload cannot be decrypted');
                            }
                            $eof = true;
                        } else {
                            throw new DecryptException('Payload cannot be decrypted');
                        }
                    } else {
                        throw new DecryptException('Payload cannot be decrypted');
                    }
                }

                if ($tag === self::TAG_FINAL && ! $eof) {
                    $remainder = fread($inputFile, 1);
                    if ($remainder !== '' && $remainder !== false) {
                        throw new DecryptException('End of stream reached before the end of the file');
                    }
                } elseif ($eof && $tag !== self::TAG_FINAL) {
                    throw new DecryptException('End of file reached before the end of the stream');
                }

                $decryptedChunk = sodium_crypto_stream_xor($encryptedChunk, $nonce, $encKey);
                if (fwrite($outputFile, $decryptedChunk) === false) {
                    throw new DecryptException('Failed to write to output file');
                }

                sodium_increment($nonce);
            }

            if (! fflush($outputFile)) {
                throw new DecryptException('Failed to flush output file');
            }
        } catch (Throwable $e) {
            ftruncate($outputFile, 0);
            throw new DecryptException('Failed to decrypt the file', previous: $e);
        } finally {
            sodium_memzero($encKey);
            sodium_memzero($authKey);
            flock($outputFile, LOCK_UN);
            fclose($inputFile);
            fclose($outputFile);
        }
    }
}
