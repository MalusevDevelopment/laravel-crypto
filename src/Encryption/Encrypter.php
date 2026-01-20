<?php

declare(strict_types=1);

namespace CodeLieutenant\LaravelCrypto\Encryption;

use CodeLieutenant\LaravelCrypto\Contracts\Encoder;
use CodeLieutenant\LaravelCrypto\Contracts\EncrypterProvider;
use CodeLieutenant\LaravelCrypto\Contracts\KeyLoader;
use CodeLieutenant\LaravelCrypto\Enums\Encryption;
use CodeLieutenant\LaravelCrypto\Support\Base64;
use Exception;
use Illuminate\Contracts\Encryption\DecryptException;
use Illuminate\Contracts\Encryption\Encrypter as EncrypterContract;
use Illuminate\Contracts\Encryption\EncryptException;
use Illuminate\Contracts\Encryption\StringEncrypter;
use Illuminate\Encryption\Encrypter as LaravelEncrypter;
use Psr\Log\LoggerInterface;
use SensitiveParameter;

final readonly class Encrypter implements EncrypterContract, StringEncrypter
{
    private string $key;

    private int $nonceSize;

    public function __construct(
        private KeyLoader $keyLoader,
        private Encoder $encoder,
        private ?LoggerInterface $logger,
        private EncrypterProvider $encrypter,
    ) {
        $this->key = $this->keyLoader->getKey();
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
            $this->logger?->error($e->getMessage(), [
                'stack' => $e->getTraceAsString(),
                'exception' => $e,
            ]);
            throw new DecryptException('Payload cannot be decrypted', previous: $e);
        }

        return match ($unserialize) {
            true => $this->encoder->decode($decrypted),
            false => $decrypted,
        };
    }

    public function getKey(): string
    {
        return $this->key;
    }

    /**
     * @return array<int, string>
     */
    public function getAllKeys(): array
    {
        return [$this->key, ...$this->getPreviousKeys()];
    }

    /**
     * @return array{}
     */
    public function getPreviousKeys(): array
    {
        return [];
    }

    public static function supported(string $key, string $cipher): bool
    {
        return match ($encType = Encryption::tryFrom($cipher)) {
            null => LaravelEncrypter::supported($key, $cipher),
            Encryption::SodiumAES256GCM => sodium_crypto_aead_aes256gcm_is_available(),
            Encryption::SodiumAEGIS256GCM => function_exists('sodium_crypto_aead_aegis256_encrypt') && strlen($key) === $encType->keySize(),
            Encryption::SodiumAEGIS128LGCM => function_exists('sodium_crypto_aead_aegis128l_encrypt') && strlen($key) === $encType->keySize(),
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

        return random_bytes($this->nonceSize);
    }
}
