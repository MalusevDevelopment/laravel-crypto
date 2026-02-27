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
 *   encryption_key  binary(89)  nullable
 *
 *   Two blob formats coexist transparently:
 *     - 0x01 (password-wrapped, 89 bytes) — after registration/login with password
 *     - 0x02 (server-wrapped,   73 bytes) — auto-enrolled users, no password needed
 *
 * ## Two-step setup for web developers
 *
 *  1. Add `use HasUserEncryption;` to your User model.
 *  2. Apply `BootPerUserEncryption` middleware to your authenticated routes.
 *
 *  That's it. Existing users get auto-enrolled transparently on first request.
 *
 * ## Registration (password available)
 *
 *   $raw = $user->initUserEncryption($request->password);
 *   $user->save();
 *   return response()->json([...])->header('X-Encryption-Token', $user->encodeEncryptionToken($raw));
 *
 * ## Login (password available)
 *
 *   return response()->json([...])->header('X-Encryption-Token', $user->issueEncryptionToken($request->password));
 *
 * ## Auto-enrollment (no password, server-side only)
 *
 *   // Done automatically by BootPerUserEncryption middleware.
 *   // For manual use (e.g. Filament hooks):
 *   [$token, $persisted] = $user->issueOrAutoEnrollToken();
 *   if ($persisted) $user->save();
 *   return response()->withHeader('X-Encryption-Token', $token);
 *
 * ## Password change
 *
 *   $user->rewrapUserEncryption($currentPassword, $newPassword);
 *   $user->password = Hash::make($newPassword);
 *   $user->save();
 *   // OR via event:
 *   PasswordChanged::dispatch($user, $currentPassword, $newPassword);
 *
 * @mixin Model
 */
trait HasUserEncryption
{
    public static function bootHasUserEncryption(): void
    {
        static::saving(static function (Model $model): void {
            // Only guard against *clearing* a key that was already set.
            // A null encryption_key is valid for brand-new records.
            /** @phpstan-ignore-next-line */
            if ($model->exists && $model->isDirty('encryption_key') && empty($model->getAttribute('encryption_key'))) {
                throw new RuntimeException(
                    'encryption_key cannot be cleared on an existing record. '.
                    'Clearing this column makes all encrypted data permanently unreadable.',
                );
            }
        });
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Initialisation
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Generate a fresh user key wrapped with the user's password.
     * Call at registration when the plaintext password is available.
     *
     * @return string Raw 32-byte user key — MUST be passed to encodeEncryptionToken(), then zeroed.
     */
    public function initUserEncryption(#[SensitiveParameter] string $password): string
    {
        $bundle = app(UserSecretManager::class)->generate($password);
        $this->setAttribute('encryption_key', $bundle['blob']);

        return $bundle['key'];
    }

    /**
     * Auto-enroll the user with a server-wrapped key (no password needed).
     * Useful for web/Filament workflows where the plaintext password is unavailable.
     *
     * @return array{token: string, persisted: bool}
     *                                               'token'     — base64url token ready for X-Encryption-Token header.
     *                                               'persisted' — true if a NEW blob was generated and set on this model.
     *                                               The caller must call $user->save() if true.
     */
    public function issueOrAutoEnrollToken(): array
    {
        $blob = $this->getRawEncryptionKeyBlob();
        $mgr = app(UserSecretManager::class);

        [$appKey, $userId] = [$this->resolveAppKeyRaw(), (string) $this->getAuthIdentifier()];

        if ($blob !== null && $mgr->isServerWrapped($blob)) {
            // Already server-enrolled — re-derive
            $key = $mgr->unwrapServerBlob($appKey, $userId, $blob);
            $token = $mgr->encodeToken($key);
            sodium_memzero($key);
            sodium_memzero($appKey);

            return ['token' => $token, 'persisted' => false];
        }

        // No blob (or password-wrapped without password) → generate new server-wrapped
        $result = $mgr->generateServerWrapped($appKey, $userId);
        $token = $mgr->encodeToken($result['key']);
        sodium_memzero($result['key']);
        sodium_memzero($appKey);

        $this->setAttribute('encryption_key', $result['blob']);

        return ['token' => $token, 'persisted' => true];
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Token issuance (password-based)
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Unwrap the stored blob with the user's password and return the token.
     * Works for both password-wrapped (0x01) and server-wrapped (0x02) blobs
     * when the password is available (server-wrapped falls back to server key).
     */
    public function issueEncryptionToken(#[SensitiveParameter] string $password): string
    {
        $blob = $this->getRawEncryptionKeyBlob();

        if ($blob === null) {
            // Never enrolled — init now
            $key = $this->initUserEncryption($password);
            $token = app(UserSecretManager::class)->encodeToken($key);
            sodium_memzero($key);

            return $token;
        }

        $mgr = app(UserSecretManager::class);

        if ($mgr->isServerWrapped($blob)) {
            // Promote server-wrapped → password-wrapped transparently
            [$appKey, $userId] = [$this->resolveAppKeyRaw(), (string) $this->getAuthIdentifier()];
            $newBlob = $mgr->rewrapServerToPassword($appKey, $userId, $blob, $password);
            sodium_memzero($appKey);
            $this->setAttribute('encryption_key', $newBlob);
            $this->save(); // @phpstan-ignore-line
            $blob = $newBlob;
        }

        $key = $mgr->unwrap($password, $blob);

        try {
            return $mgr->encodeToken($key);
        } finally {
            sodium_memzero($key);
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Password change
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Re-wrap the user key under a new password.
     * Handles both password-wrapped and server-wrapped blobs.
     * Call BEFORE hashing and saving the new password.
     */
    public function rewrapUserEncryption(
        #[SensitiveParameter] string $oldPassword,
        #[SensitiveParameter] string $newPassword,
    ): void {
        $blob = $this->getRawEncryptionKeyBlob();

        if ($blob === null) {
            // No key at all — just initialise with the new password
            $key = $this->initUserEncryption($newPassword);
            sodium_memzero($key);

            return;
        }

        $mgr = app(UserSecretManager::class);

        if ($mgr->isServerWrapped($blob)) {
            [$appKey, $userId] = [$this->resolveAppKeyRaw(), (string) $this->getAuthIdentifier()];
            $newBlob = $mgr->rewrapServerToPassword($appKey, $userId, $blob, $newPassword);
            sodium_memzero($appKey);
        } else {
            $newBlob = $mgr->rewrap($oldPassword, $newPassword, $blob);
        }

        $this->setAttribute('encryption_key', $newBlob);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Helpers
    // ─────────────────────────────────────────────────────────────────────────

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

    // ─────────────────────────────────────────────────────────────────────────
    // Private
    // ─────────────────────────────────────────────────────────────────────────

    private function resolveAppKeyRaw(): string
    {
        $key = (string) config('app.key', '');

        if (str_starts_with($key, 'base64:')) {
            $decoded = base64_decode(substr($key, 7), true);

            return $decoded !== false ? $decoded : $key;
        }

        return $key;
    }
}
