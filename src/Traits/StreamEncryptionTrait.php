<?php

declare(strict_types=1);

namespace CodeLieutenant\LaravelCrypto\Traits;

use Illuminate\Contracts\Encryption\DecryptException;
use Illuminate\Contracts\Encryption\EncryptException;
use RuntimeException;
use SensitiveParameter;
use Throwable;

trait StreamEncryptionTrait
{
    public function encryptFile(#[SensitiveParameter] string $key, string $inputFilePath, string $outputFilePath): void
    {
        $nonceSize = $this->nonceSize();
        $nonce = $nonceSize > 0 ? random_bytes($nonceSize) : '';

        $inputFile = fopen($inputFilePath, 'rb');
        $outputFile = fopen($outputFilePath, 'wb');

        try {
            if (!flock($outputFile, LOCK_EX)) {
                throw new EncryptException('Failed to acquire lock on output file');
            }
            if ($nonceSize > 0 && fwrite($outputFile, $nonce) === false) {
                throw new EncryptException('Failed to write nonce to output file');
            }

            while (!feof($inputFile)) {
                $chunk = fread($inputFile, self::CHUNK_SIZE);
                if ($chunk === false) {
                    throw new EncryptException('Failed to read from input file');
                }
                if ($chunk === '') {
                    break;
                }
                $encryptedChunk = $this->encryptChunk($key, $chunk, $nonce);
                if (fwrite($outputFile, $encryptedChunk) === false) {
                    throw new EncryptException('Failed to write to output file');
                }
                if ($nonceSize > 0) {
                    sodium_increment($nonce);
                }
            }
            if (!fflush($outputFile)) {
                throw new EncryptException('Failed to flush output file');
            }
        } catch (Throwable $e) {
            ftruncate($outputFile, 0);
            throw new EncryptException('Failed to encrypt file', previous: $e);
        } finally {
            flock($outputFile, LOCK_UN);
            fclose($inputFile);
            fclose($outputFile);
        }
    }

    public function decryptFile(#[SensitiveParameter] string $key, string $inputFilePath, string $outputFilePath): void
    {
        $nonceSize = $this->nonceSize();
        $tagSize = $this->tagSize();

        $inputFile = fopen($inputFilePath, 'rb');
        $outputFile = fopen($outputFilePath, 'wb');

        try {
            if (!flock($outputFile, LOCK_EX)) {
                throw new DecryptException('Failed to acquire lock on output file');
            }
            $nonce = $nonceSize > 0 ? fread($inputFile, $nonceSize) : '';

            if ($nonceSize > 0 && strlen($nonce) !== $nonceSize) {
                throw new DecryptException('Invalid nonce');
            }

            while (!feof($inputFile)) {
                $readSize = self::CHUNK_SIZE + $tagSize;
                $chunk = fread($inputFile, $readSize);
                if ($chunk === false) {
                    throw new DecryptException('Failed to read from input file');
                }
                if ($chunk === '') {
                    break;
                }

                try {
                    $decryptedChunk = $this->decryptChunk($key, $chunk, $nonce);
                } catch (DecryptException $e) {
                    throw $e;
                } catch (Throwable $e) {
                    throw new DecryptException('Payload cannot be decrypted', previous: $e);
                }

                if (fwrite($outputFile, $decryptedChunk) === false) {
                    throw new DecryptException('Failed to write to output file');
                }
                if ($nonceSize > 0) {
                    sodium_increment($nonce);
                }
            }
            if (!fflush($outputFile)) {
                throw new DecryptException('Failed to flush output file');
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
