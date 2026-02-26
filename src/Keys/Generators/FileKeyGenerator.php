<?php

declare(strict_types=1);

namespace CodeLieutenant\LaravelCrypto\Keys\Generators;

use CodeLieutenant\LaravelCrypto\Contracts\KeyGenerator;
use CodeLieutenant\LaravelCrypto\Encryption\File\NativeFileEncrypter;
use CodeLieutenant\LaravelCrypto\Encryption\File\SecretStreamFileEncrypter;
use CodeLieutenant\LaravelCrypto\Enums\Encryption;
use CodeLieutenant\LaravelCrypto\Traits\EnvKeySaver;
use Illuminate\Contracts\Config\Repository as Config;
use Illuminate\Encryption\Encrypter;

final readonly class FileKeyGenerator implements KeyGenerator
{
    use EnvKeySaver;

    public const string ENV = 'CRYPTO_FILE_ENCRYPTION_KEY';
    public const string ENV_PREVIOUS = 'CRYPTO_FILE_ENCRYPTION_PREVIOUS_KEYS';

    public function __construct(private Config $config) {}

    public function generate(?string $write): ?string
    {
        $old = $this->config->get('crypto.file_encryption.key');
        $oldPrevious = $this->config->get('crypto.file_encryption.previous_keys');

        $driver = $this->config->get('crypto.file_encryption.driver', SecretStreamFileEncrypter::class);

        $new = $this->formatKey(
            match ($driver) {
                SecretStreamFileEncrypter::class, 'secretstream' => sodium_crypto_secretstream_xchacha20poly1305_keygen(),
                NativeFileEncrypter::class, 'native' => match (Encryption::tryFrom($this->config->get('app.cipher'))) {
                    Encryption::SodiumAES256GCM => sodium_crypto_aead_aes256gcm_keygen(),
                    Encryption::SodiumXChaCha20Poly1305 => sodium_crypto_aead_xchacha20poly1305_ietf_keygen(),
                    Encryption::SodiumAEGIS256GCM => sodium_crypto_aead_aegis256_keygen(),
                    Encryption::SodiumAEGIS128LGCM => sodium_crypto_aead_aegis128l_keygen(),
                    null => Encrypter::generateKey($this->config->get('app.cipher')),
                },
                default => sodium_crypto_secretstream_xchacha20poly1305_keygen(),
            }
        );

        if ($write === null) {
            return $new;
        }

        $newPrevious = $old;
        if ($oldPrevious !== null && $oldPrevious !== '') {
            $newPrevious .= ',' . $oldPrevious;
        }

        $this->config->set('crypto.file_encryption.key', $new);
        $this->config->set('crypto.file_encryption.previous_keys', $newPrevious);

        $this->writeNewEnvironmentFileWith($write, [
            self::ENV => [
                'old' => $old,
                'new' => $new,
            ],
            self::ENV_PREVIOUS => [
                'old' => $oldPrevious,
                'new' => $newPrevious,
            ],
        ]);

        return null;
    }
}
