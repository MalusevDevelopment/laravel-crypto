<?php

declare(strict_types=1);

namespace CodeLieutenant\LaravelCrypto;

use CodeLieutenant\LaravelCrypto\Console\GenerateCryptoKeysCommand;
use CodeLieutenant\LaravelCrypto\Contracts\Encoder;
use CodeLieutenant\LaravelCrypto\Contracts\Hashing;
use CodeLieutenant\LaravelCrypto\Contracts\KeyLoader;
use CodeLieutenant\LaravelCrypto\Contracts\PublicKeySigning;
use CodeLieutenant\LaravelCrypto\Contracts\Signing;
use CodeLieutenant\LaravelCrypto\Encoder\IgbinaryEncoder;
use CodeLieutenant\LaravelCrypto\Encoder\JsonEncoder;
use CodeLieutenant\LaravelCrypto\Encoder\MessagePackEncoder;
use CodeLieutenant\LaravelCrypto\Encoder\PhpEncoder;
use CodeLieutenant\LaravelCrypto\Encryption\AesGcm256Encrypter;
use CodeLieutenant\LaravelCrypto\Encryption\XChaCha20Poly1305Encrypter;
use CodeLieutenant\LaravelCrypto\Enums\Encryption;
use CodeLieutenant\LaravelCrypto\Hashing\Blake2b;
use CodeLieutenant\LaravelCrypto\Hashing\HashingManager;
use CodeLieutenant\LaravelCrypto\Hashing\Sha256;
use CodeLieutenant\LaravelCrypto\Hashing\Sha512;
use CodeLieutenant\LaravelCrypto\Keys\Generators\AppKeyGenerator;
use CodeLieutenant\LaravelCrypto\Keys\Generators\Blake2BHashingKeyGenerator;
use CodeLieutenant\LaravelCrypto\Keys\Generators\EdDSASignerKeyGenerator;
use CodeLieutenant\LaravelCrypto\Keys\Generators\HmacKeyGenerator;
use CodeLieutenant\LaravelCrypto\Keys\Loaders\AppKeyLoader;
use CodeLieutenant\LaravelCrypto\Keys\Loaders\Blake2BHashingKeyLoader;
use CodeLieutenant\LaravelCrypto\Keys\Loaders\EdDSASignerKeyLoader;
use CodeLieutenant\LaravelCrypto\Keys\Loaders\HmacKeyLoader;
use CodeLieutenant\LaravelCrypto\Signing\EdDSA\EdDSA;
use CodeLieutenant\LaravelCrypto\Signing\Hmac\Blake2b as HmacBlake2b;
use CodeLieutenant\LaravelCrypto\Signing\Hmac\Sha256 as HmacSha256;
use CodeLieutenant\LaravelCrypto\Signing\Hmac\Sha512 as HmacSha512;
use CodeLieutenant\LaravelCrypto\Signing\SigningManager;
use CodeLieutenant\LaravelCrypto\Support\Random;
use Illuminate\Contracts\Config\Repository;
use Illuminate\Contracts\Encryption\Encrypter;
use Illuminate\Contracts\Foundation\Application;
use Illuminate\Encryption\Encrypter as LaravelConcreteEncrypter;
use Illuminate\Encryption\EncryptionServiceProvider;
use Override;
use Psr\Log\LoggerInterface;
use Random\Engine\Secure;
use Random\Randomizer;

class ServiceProvider extends EncryptionServiceProvider
{
    public function boot(): void
    {
        if ($this->app->runningInConsole()) {
            $this->publishes([$this->getConfigPath() => config_path('crypto.php')]);
        }
    }

    #[Override]
    public function register(): void
    {
        if ($this->app->runningInConsole()) {
            $this->registerGenerators();
            $this->commands([GenerateCryptoKeysCommand::class]);
        }

        $this->mergeConfigFrom($this->getConfigPath(), 'crypto');

        $this->registerEncoder();
        $this->registerKeyLoaders();
        $this->registerSigners();
        $this->registerHashers();
        parent::register();
    }

    protected function registerEncoder(): void
    {
        $encoders = [
            PhpEncoder::class,
            JsonEncoder::class,
            MessagePackEncoder::class,
            IgbinaryEncoder::class,
        ];

        foreach ($encoders as $encoder) {
            $this->app->singleton($encoder, function (Application $app) use ($encoder): PhpEncoder|JsonEncoder|MessagePackEncoder|IgbinaryEncoder {
                $config = $app->make(Repository::class)->get('crypto.encoder.config.'.$encoder);

                return new $encoder(...$config);
            });
        }

        $this->app->singleton(
            Encoder::class,
            $this->app->make(Repository::class)->get('crypto.encoder.driver')
        );
    }

    protected function registerKeyLoaders(): void
    {
        $this->app->singleton(
            AppKeyLoader::class,
            fn (Application $app): AppKeyLoader => AppKeyLoader::make($app->make(Repository::class))
        );
        $this->app->singleton(
            Blake2BHashingKeyLoader::class,
            fn (Application $app): Blake2BHashingKeyLoader => Blake2BHashingKeyLoader::make($app->make(Repository::class))
        );

        $this->app->singleton(
            HmacKeyLoader::class,
            fn (Application $app): HmacKeyLoader => HmacKeyLoader::make($app->make(Repository::class))
        );

        $this->app->singleton(
            EdDSASignerKeyLoader::class,
            fn (Application $app): EdDSASignerKeyLoader => EdDSASignerKeyLoader::make(
                $app->make(Repository::class),
                $app->make(LoggerInterface::class)
            )
        );
    }

    protected function registerSigners(): void
    {
        $this->app->singleton(SigningManager::class);

        $this->app->when(EdDSA::class)
            ->needs(KeyLoader::class)
            ->give(EdDSASignerKeyLoader::class);

        $hmacSigners = [
            HmacBlake2b::class,
            HmacSha256::class,
            HmacSha512::class,
        ];

        foreach ($hmacSigners as $signer) {
            $this->app->singleton($signer, function (Application $app) use ($signer): \CodeLieutenant\LaravelCrypto\Signing\Hmac\Blake2b|\CodeLieutenant\LaravelCrypto\Signing\Hmac\Sha256|\CodeLieutenant\LaravelCrypto\Signing\Hmac\Sha512 {
                $config = $app->make(Repository::class)->get('crypto.signing.config.'.$signer);
                $keyLoader = $app->make(HmacKeyLoader::class);

                return $config !== null ? new $signer($keyLoader, $config) : new $signer($keyLoader);
            });
        }

        $this->app->singleton(Signing::class, static fn (Application $app) => $app->make($app->make(Repository::class)->get('crypto.signing.driver')));

        $this->app->singleton(PublicKeySigning::class, EdDSA::class);
    }

    protected function registerHashers(): void
    {
        $hashers = [
            Blake2b::class,
            Sha256::class,
            Sha512::class,
        ];

        foreach ($hashers as $hasher) {
            $this->app->singleton($hasher, static function (Application $app) use ($hasher): Blake2b|Sha256|Sha512 {
                $params = $app->make(Repository::class)->get('crypto.hashing.config.'.$hasher);

                return $params === null ? new $hasher : new $hasher(...$params);
            });
        }

        $this->app->singleton(Hashing::class, static fn (Application $app) => $app->make($app->make(Repository::class)->get('crypto.hashing.driver')));

        $this->app->singleton(HashingManager::class);
    }

    protected function getConfigPath(): string
    {
        return __DIR__.'/../config/crypto.php';
    }

    #[Override]
    protected function registerEncrypter(): void
    {
        foreach ([AesGcm256Encrypter::class, XChaCha20Poly1305Encrypter::class] as $encryptor) {
            $this->app->singleton($encryptor);
            $this->app->when($encryptor)
                ->needs(KeyLoader::class)
                ->give(AppKeyLoader::class);
        }

        $func = static function (Application $app) {
            $cipher = $app->make(Repository::class)->get('app.cipher');

            $enc = Encryption::tryFrom($cipher);

            if ($enc === null) {
                return new LaravelConcreteEncrypter($app->make(AppKeyLoader::class)->getKey(), $cipher);
            }

            return match ($enc) {
                Encryption::SodiumAES256GCM => $app->make(AesGcm256Encrypter::class),
                Encryption::SodiumXChaCha20Poly1305 => $app->make(XChaCha20Poly1305Encrypter::class),
                Encryption::AES256GCM, Encryption::AES256CBC => new LaravelConcreteEncrypter(
                    key: $app->make(AppKeyLoader::class)->getKey(),
                    cipher: $enc->value,
                ),
            };
        };

        $this->app->singleton(Randomizer::class, fn (): Randomizer => new Randomizer(new Secure));
        $this->app->singleton(Random::class, fn (): Random => new Random($this->app->make(Randomizer::class)));
        $this->app->singleton(Encrypter::class, $func);
        $this->app->singleton('encrypter', $func);
    }

    protected function registerGenerators(): void
    {
        $this->app->singleton(AppKeyGenerator::class);
        $this->app->singleton(Blake2BHashingKeyGenerator::class);
        $this->app->singleton(HmacKeyGenerator::class);
        $this->app->singleton(EdDSASignerKeyGenerator::class);
    }
}
