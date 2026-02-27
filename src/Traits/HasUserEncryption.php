<?php

declare(strict_types=1);

namespace CodeLieutenant\LaravelCrypto\Traits;

use CodeLieutenant\LaravelCrypto\Encryption\UserKey\UserSecretManager;
use Illuminate\Database\Eloquent\Model;
use RuntimeException;
use SensitiveParameter;

/**
 * Adds per-user encryption to an Eloquent model (typically User).
 *
 * ## Required DB column
 *
 *   encryption_key  binary(88)   Self-contained blob:
 *                                salt(16) || nonce(24) || XChaCha20-Poly1305(48)
 *
 * ## Usage
 *
 *  Registration:
 *    $raw = $user->initUserEncryption($request->password);
 *    $user->save();
 *    return response()->json([...])->header('X-Encryption-Token', $user->encodeEncryptionToken($raw));
 *
 *  Login:
 *    return response()->json([...])->header('X-Encryption-Token', $user->issueEncryptionToken($request->password));
 *
 *  Password change (call BEFORE hashing the new password):
 *    $user->rewrapUserEncryption($currentPassword, $newPassword);
 *    $user->password = Hash::make($newPassword);
 *    $user->save();
 *    // OR dispatch the event:
 *    PasswordChanged::dispatch($user, $currentPassword, $newPassword);
 *
 * @mixin Model
 */
trait HasUserEncryption
{
    public static function bootHasUserEncryption(): void
    {
        static::saving(static function (Model $model): void {
            /** @phpstan-ignore-next-line */
            if ($model->exists && empty($model->getAttribute('encryption_key'))) {
                throw new RuntimeException(
                    'encryption_key cannot be empty on an existing record. ' .
                    'Clearing this column makes all encrypted data permanently unreadable.',
                );
            }
        });
    }

    /**
     * Generate a fresh user key, wrap it with the password, and set
     * the `encryption_key` attribute on this model.
     *
     * @return string  Raw 32-byte user key — MUST be zeroed by the caller
     */
    public function initUserEncryption(#[SensitiveParameter] string $password): string
    {
        $bundle = app(UserSecretManager::class)->generate($password);
        $this->setAttribute('encryption_key', $bundle['blob']);

        return $bundle['key'];
    }

    /**
     * Decrypt the stored blob and return the key base64url-encoded,
     * ready for the X-Encryption-Token response header.
     */
    public function issueEncryptionToken(#[SensitiveParameter] string $password): string
    {
        $blob = $this->getRawEncryptionKeyBlob();

        if ($blob === null) {
            throw new RuntimeException(
                'Cannot issue token: encryption_key is missing. ' .
                'Did you call initUserEncryption() at registration?',
            );
        }

        $manager = app(UserSecretManager::class);
        $key     = $manager->unwrap($password, $blob);

        try {
            return $manager->encodeToken($key);
        } finally {
            sodium_memzero($key);
        }
    }

    /**
     * Re-wrap the user key under a new password.
     * Call BEFORE hashing and saving the new password.
     */
    public function rewrapUserEncryption(
        #[SensitiveParameter] string $oldPassword,
        #[SensitiveParameter] string $newPassword,
    ): void {
        $blob = $this->getRawEncryptionKeyBlob();

        if ($blob === null) {
            throw new RuntimeException('Cannot rewrap: encryption_key is missing.');
        }

        $newBlob = app(UserSecretManager::class)->rewrap($oldPassword, $newPassword, $blob);
        $this->setAttribute('encryption_key', $newBlob);
    }

    /**
     * Encode a raw user key to base64url and zero it in place.
     *
     * @param  string  $rawKey  Will be zeroed after encoding
     */
    public function encodeEncryptionToken(#[SensitiveParameter] string &$rawKey): string
    {
        $token = app(UserSecretManager::class)->encodeToken($rawKey);
        sodium_memzero($rawKey);

        return $token;
    }

    public function getRawEncryptionKeyBlob(): ?string
    {
        /** @phpstan-ignore-next-line */
        $val = $this->getAttribute('encryption_key');

        return ($val !== null && $val !== '') ? (string) $val : null;
    }

    public function hasUserEncryptionInitialised(): bool
    {
        return $this->getRawEncryptionKeyBlob() !== null;
    }
}

