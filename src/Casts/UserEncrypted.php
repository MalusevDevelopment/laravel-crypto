<?php

declare(strict_types=1);

namespace CodeLieutenant\LaravelCrypto\Casts;

use CodeLieutenant\LaravelCrypto\Contracts\UserEncryptionContext;
use CodeLieutenant\LaravelCrypto\Encryption\UserKey\UserEncrypter;
use Illuminate\Contracts\Database\Eloquent\CastsAttributes;
use Illuminate\Database\Eloquent\Model;

/**
 * Eloquent cast that transparently encrypts/decrypts a field using the
 * per-user key from UserEncryptionContext.
 *
 * ## Usage
 *
 *   protected function casts(): array
 *   {
 *       return [
 *           'ssn'         => PasswordDerivedEncrypted::class,
 *           'secret_note' => PasswordDerivedEncrypted::class,
 *       ];
 *   }
 *
 * The X-Encryption-Token header must be present on any request that reads
 * or writes these fields, or MissingEncryptionContextException is thrown.
 */
final class UserEncrypted implements CastsAttributes
{
    /**
     * Decrypt the stored ciphertext using the current user's key.
     */
    public function get(Model $model, string $key, mixed $value, array $attributes): ?string
    {
        if ($value === null) {
            return null;
        }

        return app(UserEncrypter::class)->decryptString((string) $value);
    }

    /**
     * Encrypt the plaintext using the current user's key before storing.
     */
    public function set(Model $model, string $key, mixed $value, array $attributes): ?string
    {
        if ($value === null) {
            return null;
        }

        return app(UserEncrypter::class)->encryptString((string) $value);
    }
}
