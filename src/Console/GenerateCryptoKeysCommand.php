<?php

declare(strict_types=1);

namespace CodeLieutenant\LaravelCrypto\Console;

use CodeLieutenant\LaravelCrypto\Keys\Generators\AppKeyGenerator;
use CodeLieutenant\LaravelCrypto\Keys\Generators\Blake2BHashingKeyGenerator;
use CodeLieutenant\LaravelCrypto\Keys\Generators\EdDSASignerKeyGenerator;
use CodeLieutenant\LaravelCrypto\Keys\Generators\HmacKeyGenerator;
use Exception;
use Illuminate\Console\Command;
use Illuminate\Console\ConfirmableTrait;
use Symfony\Component\Console\Attribute\AsCommand;

#[AsCommand(name: 'crypto:keys')]
class GenerateCryptoKeysCommand extends Command
{
    use ConfirmableTrait;

    protected $signature = 'crypto:keys
        {--force   : Force the operation to run when in production}
        {--show    : Display the key instead of modifying files}
        {--no-eddsa   : Generate EdDSA(Ed25519) public and private key}
        {--no-app     : Generate application key}
        {--no-blake2b : Generate blake2b hashing key}
        {--no-hmac    : Generate Hmac key}';

    protected $description = 'Generate crypto keys (APP_KEY, EdDSA, BLAKE2B_HASHING_CRYPTO_KEY)';

    public function handle(
        EdDSASignerKeyGenerator $edDSAGenerator,
        AppKeyGenerator $appKeyGenerator,
        Blake2BHashingKeyGenerator $blake2bKeyGenerator,
        HmacKeyGenerator $hmacKeyGenerator,
    ): int {
        $show = $this->option('show');
        $eddsa = ! $this->option('no-eddsa');
        $app = ! $this->option('no-app');
        $blake2b = ! $this->option('no-blake2b');
        $hmac = ! $this->option('no-hmac');

        $proceed = $this->confirmToProceed('This operation will overwrite existing keys', fn () => $this->getLaravel()->environment('production'));

        if (! $proceed) {
            return self::FAILURE;
        }

        $write = $show ? null : app()->environmentFilePath();

        try {
            if ($eddsa) {
                $eddsaKey = $edDSAGenerator->generate($write);

                if ($show) {
                    $this->info('EdDSA Key: '.$eddsaKey);
                }
            }

            if ($app) {
                $appKey = $appKeyGenerator->generate($write);

                if ($show) {
                    $this->info('App Key: '.$appKey);
                }
            }

            if ($blake2b) {
                $blake2bKey = $blake2bKeyGenerator->generate($write);

                if ($show) {
                    $this->info('Blake2b Key: '.$blake2bKey);
                }
            }

            if ($hmac) {
                $hmacKey = $hmacKeyGenerator->generate($write);

                if ($show) {
                    $this->info('HMAC Key: '.$hmacKey);
                }
            }
        } catch (Exception $e) {
            $this->error($e->getMessage());

            return self::FAILURE;
        }

        return self::SUCCESS;
    }
}
