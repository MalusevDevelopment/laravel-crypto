<?php

declare(strict_types=1);

namespace CodeLieutenant\LaravelCrypto\Contracts;

use CodeLieutenant\LaravelCrypto\Exceptions\MissingEncryptionContextException;

/**
 * Holds the per-request decrypted user key in memory.
 *
 * Bound as `scoped` in the service container — lives for exactly one request
 * and is cleared (memzeroed) in the BootPerUserEncryption middleware's
 * finally block.
 */
interface UserEncryptionContext
{
    /** Store the raw 32-byte key. Overwrites any previously held value. */
    public function set(string $key): void;

    /**
     * Retrieve the raw key.
     *
     * @throws MissingEncryptionContextException when no key has been loaded.
     */
    public function get(): string;

    /** Return true if a key is currently loaded. */
    public function has(): bool;

    /** Zero the key bytes and clear the internal state. */
    public function clear(): void;
}
