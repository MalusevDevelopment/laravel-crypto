<?php

declare(strict_types=1);

namespace CodeLieutenant\LaravelCrypto\Encryption;

use CodeLieutenant\LaravelCrypto\Contracts\Encoder;
use CodeLieutenant\LaravelCrypto\Contracts\KeyLoader;
use CodeLieutenant\LaravelCrypto\Encoder\JsonEncoder;
use CodeLieutenant\LaravelCrypto\Support\Base64;
use CodeLieutenant\LaravelCrypto\Traits\Crypto;
use Exception;
use Illuminate\Contracts\Encryption\DecryptException;
use Illuminate\Contracts\Encryption\Encrypter;
use Illuminate\Contracts\Encryption\EncryptException;
use Illuminate\Contracts\Encryption\StringEncrypter;
use Psr\Log\LoggerInterface;
use SensitiveParameter;

final readonly class AesGcm256Encrypter implements Encrypter, StringEncrypter
{
    use Crypto;

    public function __construct(
        private KeyLoader $keyLoader,
        private Encoder $encoder = new JsonEncoder,
        private ?LoggerInterface $logger = null,
    ) {}

    public function encrypt(#[SensitiveParameter] $value, $serialize = true): string
    {
        $serialized = match ($serialize) {
            true => $this->encoder->encode($value),
            false => $value,
        };

        try {
            $nonce = $this->generateNonce();
            $encrypted = sodium_crypto_aead_aes256gcm_encrypt((string) $serialized, $nonce, $nonce, $this->getKey());

            return Base64::constantUrlEncodeNoPadding($nonce.$encrypted);
        } catch (Exception $e) {
            $this->logger?->error($e->getMessage(), [
                'exception' => $e,
                'stack' => $e->getTraceAsString(),
            ]);
            throw new EncryptException('Value cannot be encrypted');
        }
    }

    public function decrypt($payload, $unserialize = true)
    {
        $decoded = Base64::constantUrlDecodeNopadding($payload);
        $nonce = substr($decoded, 0, self::nonceSize());
        $cipherText = substr($decoded, self::nonceSize());

        try {
            $decrypted = sodium_crypto_aead_aes256gcm_decrypt($cipherText, $nonce, $nonce, $this->keyLoader->getKey());
        } catch (Exception $e) {
            $this->logger?->error($e->getMessage(), [
                'stack' => $e->getTraceAsString(),
                'exception' => $e,
            ]);
            throw new DecryptException('Payload cannot be decrypted');
        }

        return match ($unserialize) {
            true => $this->encoder->decode($decrypted),
            false => $decrypted,
        };
    }

    public static function nonceSize(): int
    {
        return SODIUM_CRYPTO_AEAD_AES256GCM_NPUBBYTES;
    }
}
