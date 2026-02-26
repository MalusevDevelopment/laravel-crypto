<?php

declare(strict_types=1);

namespace CodeLieutenant\LaravelCrypto\Encryption;

use CodeLieutenant\LaravelCrypto\Contracts\Encoder;
use CodeLieutenant\LaravelCrypto\Contracts\EncrypterProvider;
use CodeLieutenant\LaravelCrypto\Contracts\FileEncrypter;
use CodeLieutenant\LaravelCrypto\Contracts\KeyLoader;
use CodeLieutenant\LaravelCrypto\Enums\Encryption;
use CodeLieutenant\LaravelCrypto\Support\Base64;
use CodeLieutenant\LaravelCrypto\Support\Random;
use Exception;
use Illuminate\Contracts\Encryption\DecryptException;
use Illuminate\Contracts\Encryption\Encrypter as EncrypterContract;
use Illuminate\Contracts\Encryption\EncryptException;
use Illuminate\Contracts\Encryption\StringEncrypter;
use Illuminate\Support\Traits\Macroable;
use Psr\Log\LoggerInterface;
use Random\Randomizer;
use SensitiveParameter;
use Throwable;

final class Encrypter implements EncrypterContract, StringEncrypter
{
    use Macroable;

    protected readonly string $key;

    protected readonly int $nonceSize;

    public function __construct(
        protected readonly KeyLoader $keyLoader,
        protected readonly Encoder $encoder,
        protected readonly ?LoggerInterface $logger,
        protected readonly EncrypterProvider $encrypter,
        protected readonly ?FileEncrypter $fileEncrypter = null,
        protected readonly Random $random = new Random(new Randomizer),
        protected readonly ?KeyLoader $fileKeyLoader = null,
    ) {
        $this->key = (string) $this->keyLoader->getKey();
        $this->nonceSize = $this->encrypter->nonceSize();
    }

    public function encrypt(#[SensitiveParameter] $value, $serialize = true): string
    {
        $serialized = match ($serialize) {
            true => $this->encoder->encode($value),
            false => $value,
        };

        try {
            $nonce = $this->generateNonce();
            $encrypted = $this->encrypter->encrypt($this->key, (string) $serialized, $nonce);

            return Base64::urlEncodeNoPadding($nonce.$encrypted);
        } catch (Exception $e) {
            $this->logger?->error($e->getMessage(), [
                'exception' => $e,
                'stack' => $e->getTraceAsString(),
            ]);
            throw new EncryptException('Value cannot be encrypted', previous: $e);
        }
    }

    public function decrypt($payload, $unserialize = true)
    {
        $decoded = Base64::urlDecode($payload);

        $nonce = substr($decoded, 0, $this->nonceSize);
        $cipherText = substr($decoded, $this->nonceSize);

        try {
            $decrypted = $this->encrypter->decrypt($this->key, $cipherText, $nonce);
        } catch (Exception $e) {
            return $this->decryptWithPreviousKeys($cipherText, $nonce, $unserialize, $e);
        }

        return match ($unserialize) {
            true => $this->encoder->decode($decrypted),
            false => $decrypted,
        };
    }

    /**
     * @throws DecryptException
     */
    private function decryptWithPreviousKeys(string $cipherText, string $nonce, bool $unserialize, ?Exception $exception = null): mixed
    {
        foreach ($this->getPreviousKeys() as $key) {
            try {
                $decrypted = $this->encrypter->decrypt($key, $cipherText, $nonce);

                return match ($unserialize) {
                    true => $this->encoder->decode($decrypted),
                    false => $decrypted,
                };
            } catch (Throwable) {
                //
            }
        }

        $this->logger?->error($exception?->getMessage() ?? 'Payload cannot be decrypted', [
            'stack' => $exception?->getTraceAsString(),
            'exception' => $exception,
        ]);

        throw new DecryptException('Payload cannot be decrypted', previous: $exception);
    }

    public function getKey(): string
    {
        return $this->key;
    }

    public function getFileKey(): string
    {
        return (string) ($this->fileKeyLoader ?? $this->keyLoader)->getKey();
    }

    /**
     * @return array<int, string>
     */
    public function getAllKeys(): array
    {
        return [$this->key, ...$this->getPreviousKeys()];
    }

    /**
     * @return array<int, string>
     */
    public function getPreviousKeys(): array
    {
        return $this->keyLoader->getPreviousKeys();
    }

    /**
     * @return array<int, string>
     */
    public function getPreviousFileKeys(): array
    {
        return ($this->fileKeyLoader ?? $this->keyLoader)->getPreviousKeys();
    }

    public function getFileEncrypter(): ?FileEncrypter
    {
        return $this->fileEncrypter;
    }

    public function getLogger(): ?LoggerInterface
    {
        return $this->logger;
    }

    public static function supported(string $key, string $cipher): bool
    {
        $encType = Encryption::tryFrom($cipher);

        if ($encType === null) {
            $cipher = strtolower($cipher);

            if ($cipher === 'aes-128-cbc') {
                return strlen($key) === 16;
            }

            if ($cipher === 'aes-256-cbc') {
                return strlen($key) === 32;
            }

            if ($cipher === 'aes-128-gcm') {
                return strlen($key) === 16;
            }

            if ($cipher === 'aes-256-gcm') {
                return strlen($key) === 32;
            }

            return false;
        }

        return match ($encType) {
            Encryption::SodiumAES256GCM => sodium_crypto_aead_aes256gcm_is_available(),
            Encryption::SodiumAEGIS256GCM => function_exists('sodium_crypto_aead_aegis256_encrypt') && strlen($key) === $encType->keySize(),
            Encryption::SodiumAEGIS128LGCM => function_exists('sodium_crypto_aead_aegis128l_encrypt') && strlen($key) === $encType->keySize(),
            Encryption::SodiumSecretBox => strlen($key) === $encType->keySize(),
            default => strlen($key) === $encType->keySize()
        };
    }

    public function encryptString($value): string
    {
        return $this->encrypt($value, false);
    }

    public function decryptString($payload): string
    {
        return $this->decrypt($payload, false);
    }

    public function generateNonce(?string $previous = null): string
    {
        if ($previous !== null) {
            $copy = $previous;
            sodium_increment($copy);

            return $copy;
        }

        return $this->random->bytes($this->nonceSize);
    }
}
