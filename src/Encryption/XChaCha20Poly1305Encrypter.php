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

final readonly class XChaCha20Poly1305Encrypter implements Encrypter, StringEncrypter
{
    use Crypto;

    public function __construct(
        private KeyLoader $keyLoader,
        private Encoder $encoder = new JsonEncoder,
        private ?LoggerInterface $logger = null,
    ) {}

    public function encrypt($value, $serialize = true): string
    {
        if ($serialize) {
            $value = $this->encoder->encode($value);
        }

        try {
            $nonce = $this->generateNonce();
            $encrypted = sodium_crypto_aead_xchacha20poly1305_ietf_encrypt(
                (string) $value,
                $nonce,
                $nonce,
                $this->keyLoader->getKey()
            );

            return Base64::constantUrlEncodeNoPadding($nonce.$encrypted);
        } catch (Exception $e) {
            $this->logger?->error($e->getMessage(), [
                'exception' => $e,
                'value' => $value,
                'serialize' => $serialize,
            ]);
            throw new EncryptException('Value cannot be encrypted '.$e->getMessage());
        }
    }

    public function decrypt($payload, $unserialize = true)
    {
        $decoded = Base64::constantUrlDecodeNoPadding($payload);
        $nonce = substr($decoded, 0, self::nonceSize());
        $cipherText = substr($decoded, self::nonceSize());

        try {
            $decrypted = sodium_crypto_aead_xchacha20poly1305_ietf_decrypt(
                $cipherText,
                $nonce,
                $nonce,
                $this->keyLoader->getKey()
            );
        } catch (Exception $e) {
            $this->logger?->error($e->getMessage(), [
                'exception' => $e,
                'serialize' => $unserialize,
            ]);
            throw new DecryptException('Payload cannot be decrypted');
        }

        if ($unserialize) {
            return $this->encoder->decode($decrypted);
        }

        return $decrypted;
    }

    public static function nonceSize(): int
    {
        return SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES;
    }
}
