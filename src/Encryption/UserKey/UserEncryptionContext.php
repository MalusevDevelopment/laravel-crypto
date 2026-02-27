<?php

declare(strict_types=1);

namespace CodeLieutenant\LaravelCrypto\Encryption\UserKey;

use CodeLieutenant\LaravelCrypto\Contracts\UserEncryptionContext as UserEncryptionContextContract;
use CodeLieutenant\LaravelCrypto\Exceptions\MissingEncryptionContextException;

/**
 * Request-scoped holder for the per-user decrypted key.
 *
 * Registered as `scoped` — one instance per HTTP request.
 * The BootPerUserEncryption middleware clears this in its finally block.
 */
final class UserEncryptionContext implements UserEncryptionContextContract
{
    private ?string $key = null;

    public function set(string $key): void
    {
        if ($this->key !== null) {
            sodium_memzero($this->key);
        }

        $this->key = $key;
    }

    public function get(): string
    {
        if ($this->key === null) {
            throw new MissingEncryptionContextException;
        }

        return $this->key;
    }

    public function has(): bool
    {
        return $this->key !== null;
    }

    public function clear(): void
    {
        if ($this->key !== null) {
            sodium_memzero($this->key);
            $this->key = null;
        }
    }

    public function __destruct()
    {
        $this->clear();
    }
}

