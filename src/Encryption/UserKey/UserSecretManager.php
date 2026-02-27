<?php

declare(strict_types=1);

namespace CodeLieutenant\LaravelCrypto\Encryption\UserKey;

use CodeLieutenant\LaravelCrypto\Support\Base64;
use RuntimeException;
use SensitiveParameter;

/**
 * Manages the per-user encryption key lifecycle.
 *
 * ## Scheme
 *
 * Each user owns one random 32-byte key (`user_key`).
 *
 * At registration:
 *   1. Generate random `user_key` (32 bytes).
 *   2. Generate random Argon2id salt (16 bytes) and nonce (24 bytes).
 *   3. Derive a wrapping key from the user's password via Argon2id(password, salt).
 *   4. Encrypt `user_key` with XChaCha20-Poly1305, using `salt||nonce` as AD.
 *   5. Store the single `encryption_key` blob (88 bytes) in the DB.
 *   6. Return `user_key` as `X-Encryption-Token` (base64url). Never stored.
 *
 * On every subsequent request:
 *   Frontend sends the token back. Middleware decodes it (base64url → 32 bytes)
 *   and loads it into `UserEncryptionContext`. No DB access, no Argon2id.
 *
 * On password change:
 *   `rewrap(oldPassword, newPassword, blob)` — self-contained, no external salt.
 *
 * ## Blob format  (single `encryption_key` column, binary, 88 bytes)
 *
 *   salt(16) || nonce(24) || XChaCha20-Poly1305(key=32, tag=16) = 88 bytes
 *
 *   Additional Data (AD) for the AEAD MAC = salt || nonce.
 *   The AD is fed into the MAC but not encrypted, binding the ciphertext to
 *   its exact salt+nonce pair. Swapping either component from another blob
 *   breaks the authentication tag — preventing blob-splicing attacks.
 *
 * @see https://doc.libsodium.org/password_hashing/default_phf
 * @see https://doc.libsodium.org/secret-key_cryptography/aead/chacha20-poly1305/xchacha20-poly1305_construction
 */
final readonly class UserSecretManager
{
    /** Size of the random user key. */
    public const int KEY_BYTES = SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_KEYBYTES; // 32

    /** Total size of the stored blob: salt + nonce + ciphertext(key + tag). */
    public const int BLOB_BYTES =
        SODIUM_CRYPTO_PWHASH_SALTBYTES                              // 16  — Argon2id salt
        + SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES      // 24  — nonce
        + SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_KEYBYTES       // 32  — encrypted key
        + SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_ABYTES;        // 16  — Poly1305 tag
        // total = 88

    private const int SALT_BYTES         = SODIUM_CRYPTO_PWHASH_SALTBYTES;
    private const int NONCE_BYTES        = SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES;
    private const int WRAPPING_KEY_BYTES = SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_KEYBYTES;

    public function __construct(
        private int $opsLimit = SODIUM_CRYPTO_PWHASH_OPSLIMIT_INTERACTIVE,
        private int $memLimit = SODIUM_CRYPTO_PWHASH_MEMLIMIT_INTERACTIVE,
    ) {}

    // -------------------------------------------------------------------------
    // Registration
    // -------------------------------------------------------------------------

    /**
     * @return array{key: string, blob: string}
     *   'key'  — raw 32-byte user key. Send as X-Encryption-Token, then zero.
     *   'blob' — 88-byte self-contained blob. Persist in `encryption_key` column.
     */
    public function generate(#[SensitiveParameter] string $password): array
    {
        $key  = random_bytes(self::KEY_BYTES);
        $blob = $this->wrapKey($key, $password);

        return ['key' => $key, 'blob' => $blob];
    }

    // -------------------------------------------------------------------------
    // Login
    // -------------------------------------------------------------------------

    /**
     * Decrypt the blob and return the raw user_key.
     * Caller MUST zero the return value with sodium_memzero() after use.
     */
    public function unwrap(
        #[SensitiveParameter] string $password,
        #[SensitiveParameter] string $blob,
    ): string {
        [$salt, $nonce, $ciphertext] = $this->splitBlob($blob);

        $wrappingKey = $this->deriveWrappingKey($password, $salt);

        try {
            $result = sodium_crypto_aead_xchacha20poly1305_ietf_decrypt(
                $ciphertext, $salt . $nonce, $nonce, $wrappingKey,
            );
        } finally {
            sodium_memzero($wrappingKey);
        }

        if ($result === false) {
            throw new RuntimeException('Failed to unwrap encryption key: authentication tag mismatch.');
        }

        return $result;
    }

    // -------------------------------------------------------------------------
    // Password change
    // -------------------------------------------------------------------------

    /**
     * Re-wrap the user_key under a new password and return a fresh blob.
     * The user_key is unchanged — all encrypted data remains readable.
     *
     * @return string  New 88-byte blob to persist
     */
    public function rewrap(
        #[SensitiveParameter] string $oldPassword,
        #[SensitiveParameter] string $newPassword,
        #[SensitiveParameter] string $blob,
    ): string {
        $key = $this->unwrap($oldPassword, $blob);

        try {
            return $this->wrapKey($key, $newPassword);
        } finally {
            sodium_memzero($key);
        }
    }

    // -------------------------------------------------------------------------
    // Token encoding
    // -------------------------------------------------------------------------

    public function encodeToken(#[SensitiveParameter] string $key): string
    {
        return Base64::urlEncodeNoPadding($key);
    }

    public function decodeToken(string $token): ?string
    {
        if ($token === '') {
            return null;
        }

        $raw = Base64::urlDecode($token);

        if ($raw === '' || $raw === false || strlen($raw) !== self::KEY_BYTES) {
            return null;
        }

        return $raw;
    }

    // -------------------------------------------------------------------------
    // Private helpers
    // -------------------------------------------------------------------------

    /**
     * Wrap a key with a fresh random salt + nonce, return the self-contained blob.
     *
     * Blob = salt(16) || nonce(24) || ciphertext(48)
     *
     * AD = salt || nonce — binds the MAC to this exact salt+nonce pair so
     * neither component can be swapped from a different blob.
     */
    private function wrapKey(
        #[SensitiveParameter] string $key,
        #[SensitiveParameter] string $password,
    ): string {
        $salt        = random_bytes(self::SALT_BYTES);
        $nonce       = random_bytes(self::NONCE_BYTES);
        $wrappingKey = $this->deriveWrappingKey($password, $salt);

        try {
            $ciphertext = sodium_crypto_aead_xchacha20poly1305_ietf_encrypt(
                $key, $salt . $nonce, $nonce, $wrappingKey,
            );
        } finally {
            sodium_memzero($wrappingKey);
        }

        return $salt . $nonce . $ciphertext;
    }

    private function deriveWrappingKey(
        #[SensitiveParameter] string $password,
        string $salt,
    ): string {
        return sodium_crypto_pwhash(
            self::WRAPPING_KEY_BYTES,
            $password,
            $salt,
            $this->opsLimit,
            $this->memLimit,
            SODIUM_CRYPTO_PWHASH_ALG_ARGON2ID13,
        );
    }

    /** @return array{string, string, string}  [salt, nonce, ciphertext] */
    private function splitBlob(string $blob): array
    {
        if (strlen($blob) !== self::BLOB_BYTES) {
            throw new RuntimeException(
                sprintf('Invalid encryption_key blob length: expected %d, got %d.', self::BLOB_BYTES, strlen($blob)),
            );
        }

        $salt       = substr($blob, 0, self::SALT_BYTES);
        $nonce      = substr($blob, self::SALT_BYTES, self::NONCE_BYTES);
        $ciphertext = substr($blob, self::SALT_BYTES + self::NONCE_BYTES);

        return [$salt, $nonce, $ciphertext];
    }
}

