<?php

declare(strict_types=1);

namespace CodeLieutenant\LaravelCrypto\Keys\Loaders;

use CodeLieutenant\LaravelCrypto\Contracts\KeyLoader;
use CodeLieutenant\LaravelCrypto\Contracts\UserEncryptionContext;

/**
 * KeyLoader implementation that reads the key from the per-request
 * UserEncryptionContext. Used by the PasswordDerivedEncrypted cast.
 */
final readonly class PerUserKeyLoader implements KeyLoader
{
    public function __construct(
        private UserEncryptionContext $context,
    ) {}

    public function getKey(): string|array
    {
        return $this->context->get();
    }

    public function getPreviousKeys(): array
    {
        return [];
    }
}


