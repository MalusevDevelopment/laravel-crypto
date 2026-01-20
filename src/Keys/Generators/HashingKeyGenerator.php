<?php

declare(strict_types=1);

namespace CodeLieutenant\LaravelCrypto\Keys\Generators;

use CodeLieutenant\LaravelCrypto\Contracts\KeyGenerator;
use CodeLieutenant\LaravelCrypto\Facades\Random;
use CodeLieutenant\LaravelCrypto\Traits\EnvKeySaver;
use Illuminate\Contracts\Config\Repository;

abstract class HashingKeyGenerator implements KeyGenerator
{
    use EnvKeySaver;

    protected static int $KEY_SIZE;

    protected static string $ENV;

    protected static string $CONFIG_KEY_PATH;

    public function __construct(
        protected Repository $config,
    ) {}

    public function generate(?string $write): ?string
    {
        $old = $this->config->get(static::$CONFIG_KEY_PATH);
        $new = $this->formatKey(Random::bytes(static::$KEY_SIZE));

        $this->config->set(static::$CONFIG_KEY_PATH, $new);

        if ($write === null) {
            return $new;
        }

        $this->writeNewEnvironmentFileWith($write, [
            static::$ENV => [
                'old' => $old ?? '',
                'new' => $new,
            ],
        ]);

        return null;
    }
}
