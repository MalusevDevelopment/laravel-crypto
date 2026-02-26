<?php

declare(strict_types=1);

namespace CodeLieutenant\LaravelCrypto\Keys\Generators;

use CodeLieutenant\LaravelCrypto\Contracts\KeyGenerator;
use CodeLieutenant\LaravelCrypto\Enums\Encryption;
use CodeLieutenant\LaravelCrypto\Keys\Loaders\AppKeyLoader;
use CodeLieutenant\LaravelCrypto\Traits\EnvKeySaver;
use Illuminate\Contracts\Config\Repository as Config;
use Illuminate\Encryption\Encrypter;

final readonly class AppKeyGenerator implements KeyGenerator
{
    use EnvKeySaver;

    private const string CONFIG_CIPHER_PATH = 'app.cipher';

    private const string CONFIG_KEY_PATH = 'app.key';

    public const string ENV = 'APP_KEY';

    public const string ENV_PREVIOUS = 'APP_PREVIOUS_KEYS';

    public function __construct(private Config $config) {}

    public function generate(?string $write): ?string
    {
        $old = $this->config->get(self::CONFIG_KEY_PATH);
        if (is_array($old)) {
            $old = implode(',', $old);
        }
        $oldPrevious = $this->config->get(AppKeyLoader::CONFIG_PREVIOUS_KEYS_PATH);
        if (is_array($oldPrevious)) {
            $oldPrevious = implode(',', $oldPrevious);
        }
        $cipher = $this->config->get(self::CONFIG_CIPHER_PATH);

        $new = $this->formatKey(
            match (Encryption::tryFrom($cipher)) {
                Encryption::SodiumAES256GCM => sodium_crypto_aead_aes256gcm_keygen(),
                Encryption::SodiumXChaCha20Poly1305 => sodium_crypto_aead_xchacha20poly1305_ietf_keygen(),
                Encryption::SodiumAEGIS256GCM => sodium_crypto_aead_aegis256_keygen(),
                Encryption::SodiumAEGIS128LGCM => sodium_crypto_aead_aegis128l_keygen(),
                null => Encrypter::generateKey($cipher),
            }
        );

        if ($write === null) {
            return $new;
        }

        $newPrevious = $old;

        if ($oldPrevious !== null && $oldPrevious !== '') {
            $newPrevious .= ',' . $oldPrevious;
        }

        $this->config->set(self::CONFIG_KEY_PATH, $new);
        $this->config->set(AppKeyLoader::CONFIG_PREVIOUS_KEYS_PATH, $newPrevious);

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
