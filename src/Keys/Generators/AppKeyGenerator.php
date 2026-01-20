<?php

declare(strict_types=1);

namespace CodeLieutenant\LaravelCrypto\Keys\Generators;

use CodeLieutenant\LaravelCrypto\Contracts\KeyGenerator;
use CodeLieutenant\LaravelCrypto\Enums\Encryption;
use CodeLieutenant\LaravelCrypto\Traits\EnvKeySaver;
use Illuminate\Contracts\Config\Repository;
use Illuminate\Encryption\Encrypter;

final readonly class AppKeyGenerator implements KeyGenerator
{
    use EnvKeySaver;

    private const string CONFIG_CIPHER_PATH = 'app.cipher';

    private const string CONFIG_KEY_PATH = 'app.key';

    public const string ENV = 'APP_KEY';

    public function __construct(private Repository $config) {}

    public function generate(?string $write): ?string
    {
        $old = $this->config->get(self::CONFIG_KEY_PATH);
        $cipher = $this->config->get(self::CONFIG_CIPHER_PATH);

        $new = $this->formatKey(
            match (Encryption::tryFrom($cipher)) {
                Encryption::SodiumAES256GCM => sodium_crypto_aead_aes256gcm_keygen(),
                Encryption::SodiumXChaCha20Poly1305 => sodium_crypto_aead_xchacha20poly1305_ietf_keygen(),
                default => Encrypter::generateKey($cipher),
            }
        );

        if ($write === null) {
            return $new;
        }

        $this->config->set(self::CONFIG_KEY_PATH, $new);

        $this->writeNewEnvironmentFileWith($write, [
            self::ENV => [
                'old' => $old,
                'new' => $new,
            ],
        ]);

        return null;
    }
}
