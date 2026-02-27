<?php

declare(strict_types=1);

namespace CodeLieutenant\LaravelCrypto\Encryption\UserKey;

use CodeLieutenant\LaravelCrypto\Support\Base64;
use RuntimeException;
use SensitiveParameter;

/**
 * Manages the per-user encryption key lifecycle.
 *
 * ## Two wrapping modes
 *
 * ### Mode 1 — Password-wrapped  (version byte = 0x01)
 *
 *   Used when the plaintext password is available (registration, login).
 *   Wrapping key derived via Argon2id. Requires the user to send the
 *   X-Encryption-Token on every request.
 *
 *   Blob: 0x01 || salt(16) || nonce(24) || XChaCha20-Poly1305(key, AD=salt||nonce) = 89 bytes
 *
 * ### Mode 2 — Server-wrapped  (version byte = 0x02)
 *
 *   Used for auto-enrollment of users who don't have a key yet.
 *   Wrapping key derived via BLAKE2b-HKDF(appKey, userId) — fast, no Argon2id.
 *   Middleware re-derives the wrapping key each request without any user input.
 *   The token is STILL issued to the frontend and sent back on every request
 *   (same UX). On the next password-change the blob is promoted to mode 1.
 *
 *   Blob: 0x02 || nonce(24) || XChaCha20-Poly1305(key, AD=userId_bytes) = 73 bytes
 *
 * @see https://doc.libsodium.org/password_hashing/default_phf
 * @see https://doc.libsodium.org/secret-key_cryptography/aead/chacha20-poly1305/xchacha20-poly1305_construction
 */
final readonly class UserSecretManager
{
    /** Size of the random user key. */
    public const int KEY_BYTES = SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_KEYBYTES; // 32

    // ── Mode 1 (password-wrapped) sizes ─────────────────────────────────────
    public const int BLOB_BYTES =
        1                                                            // version byte
        + SODIUM_CRYPTO_PWHASH_SALTBYTES                             // 16  — Argon2id salt
        + SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES       // 24  — nonce
        + SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_KEYBYTES        // 32  — encrypted key
        + SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_ABYTES;         // 16  — Poly1305 tag
        // total = 89

    // ── Mode 2 (server-wrapped) sizes ────────────────────────────────────────
    public const int SERVER_BLOB_BYTES =
        1                                                            // version byte
        + SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES       // 24  — nonce
        + SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_KEYBYTES        // 32  — encrypted key
        + SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_ABYTES;         // 16  — Poly1305 tag
        // total = 73

    public const int VERSION_PASSWORD = 0x01;
    public const int VERSION_SERVER   = 0x02;

    private const int SALT_BYTES         = SODIUM_CRYPTO_PWHASH_SALTBYTES;
    private const int NONCE_BYTES        = SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES;
    private const int WRAPPING_KEY_BYTES = SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_KEYBYTES;

    /** Context string for BLAKE2b key derivation (server-wrap mode). */
    private const string HKDF_CONTEXT = 'lc-user-key-wrap-v1';

    public function __construct(
        private int $opsLimit = SODIUM_CRYPTO_PWHASH_OPSLIMIT_INTERACTIVE,
        private int $memLimit = SODIUM_CRYPTO_PWHASH_MEMLIMIT_INTERACTIVE,
    ) {}

    // ─────────────────────────────────────────────────────────────────────────
    // Mode 1 — Password-wrapped (Argon2id)
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Generate a new user key wrapped with the user's password.
     *
     * @return array{key: string, blob: string}
     *   'key'  — raw 32-byte user key. Encode as X-Encryption-Token then zero.
     *   'blob' — 89-byte self-contained blob to persist in `encryption_key`.
     */
    public function generate(#[SensitiveParameter] string $password): array
    {
        $key  = random_bytes(self::KEY_BYTES);
        $blob = $this->wrapWithPassword($key, $password);

        return ['key' => $key, 'blob' => $blob];
    }

    /**
     * Unwrap a password-wrapped blob and return the raw user key.
     * Caller MUST zero the return value with sodium_memzero() after use.
     */
    public function unwrap(
        #[SensitiveParameter] string $password,
        #[SensitiveParameter] string $blob,
    ): string {
        $version = $this->readVersion($blob);

        if ($version === self::VERSION_SERVER) {
            throw new RuntimeException(
                'This blob is server-wrapped. Use unwrapServerBlob() instead.',
            );
        }

        return $this->unwrapPasswordBlob($password, $blob);
    }

    /**
     * Re-wrap a password-wrapped blob under a new password.
     * The user_key itself is unchanged — all encrypted data stays readable.
     */
    public function rewrap(
        #[SensitiveParameter] string $oldPassword,
        #[SensitiveParameter] string $newPassword,
        #[SensitiveParameter] string $blob,
    ): string {
        $version = $this->readVersion($blob);

        $key = $version === self::VERSION_SERVER
            ? throw new RuntimeException('Use rewrapServerToPassword() to promote a server-wrapped blob.')
            : $this->unwrapPasswordBlob($oldPassword, $blob);

        try {
            return $this->wrapWithPassword($key, $newPassword);
        } finally {
            sodium_memzero($key);
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Mode 2 — Server-wrapped (BLAKE2b-HKDF, no Argon2id)
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Generate a new user key wrapped with a server-side HKDF key.
     * Used for auto-enrollment — no password required.
     *
     * @param  string  $appKey   Raw 32-byte application key (from config('app.key'))
     * @param  string  $userId   Stable unique user identifier (cast to string)
     * @return array{key: string, blob: string}
     */
    public function generateServerWrapped(
        #[SensitiveParameter] string $appKey,
        string $userId,
    ): array {
        $key  = random_bytes(self::KEY_BYTES);
        $blob = $this->wrapWithServerKey($key, $appKey, $userId);

        return ['key' => $key, 'blob' => $blob];
    }

    /**
     * Unwrap a server-wrapped blob without the user's password.
     */
    public function unwrapServerBlob(
        #[SensitiveParameter] string $appKey,
        string $userId,
        #[SensitiveParameter] string $blob,
    ): string {
        $version = $this->readVersion($blob);

        if ($version !== self::VERSION_SERVER) {
            throw new RuntimeException(
                'This blob is password-wrapped. Use unwrap() instead.',
            );
        }

        return $this->doUnwrapServerBlob($appKey, $userId, $blob);
    }

    /**
     * Promote a server-wrapped blob to a password-wrapped blob.
     * Call this when the user sets / changes their password.
     *
     * This is transparent — the user_key stays the same.
     */
    public function rewrapServerToPassword(
        #[SensitiveParameter] string $appKey,
        string $userId,
        #[SensitiveParameter] string $blob,
        #[SensitiveParameter] string $newPassword,
    ): string {
        $key = $this->doUnwrapServerBlob($appKey, $userId, $blob);

        try {
            return $this->wrapWithPassword($key, $newPassword);
        } finally {
            sodium_memzero($key);
        }
    }

    /**
     * Universal unwrap: handles both blob versions automatically.
     *
     * Pass $appKey + $userId for server-wrapped blobs.
     * Pass $password for password-wrapped blobs.
     * The method inspects the version byte and delegates accordingly.
     *
     * @param  string|null  $password  Required for version 0x01 blobs
     * @param  string|null  $appKey    Required for version 0x02 blobs
     * @param  string|null  $userId    Required for version 0x02 blobs
     */
    public function unwrapAny(
        #[SensitiveParameter] string $blob,
        #[SensitiveParameter] ?string $password = null,
        #[SensitiveParameter] ?string $appKey = null,
        ?string $userId = null,
    ): string {
        return match ($this->readVersion($blob)) {
            self::VERSION_PASSWORD => $this->unwrapPasswordBlob($password ?? throw new RuntimeException('Password required for password-wrapped blob.'), $blob),
            self::VERSION_SERVER   => $this->doUnwrapServerBlob($appKey ?? throw new RuntimeException('App key required for server-wrapped blob.'), $userId ?? throw new RuntimeException('User ID required for server-wrapped blob.'), $blob),
            default                => throw new RuntimeException('Unknown blob version.'),
        };
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Token encoding
    // ─────────────────────────────────────────────────────────────────────────

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

    // ─────────────────────────────────────────────────────────────────────────
    // Version inspection
    // ─────────────────────────────────────────────────────────────────────────

    public function blobVersion(string $blob): int
    {
        return $this->readVersion($blob);
    }

    public function isServerWrapped(string $blob): bool
    {
        return strlen($blob) >= 1 && $this->readVersion($blob) === self::VERSION_SERVER;
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Private — Mode 1 helpers
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Wrap a key with the user's password (Argon2id + XChaCha20-Poly1305).
     * Blob: 0x01 || salt(16) || nonce(24) || ciphertext(48) = 89 bytes
     * AD  = salt || nonce
     */
    private function wrapWithPassword(
        #[SensitiveParameter] string $key,
        #[SensitiveParameter] string $password,
    ): string {
        $salt        = random_bytes(self::SALT_BYTES);
        $nonce       = random_bytes(self::NONCE_BYTES);
        $wrappingKey = $this->derivePasswordWrappingKey($password, $salt);

        try {
            $ct = sodium_crypto_aead_xchacha20poly1305_ietf_encrypt(
                $key, $salt . $nonce, $nonce, $wrappingKey,
            );
        } finally {
            sodium_memzero($wrappingKey);
        }

        return chr(self::VERSION_PASSWORD) . $salt . $nonce . $ct;
    }

    private function unwrapPasswordBlob(
        #[SensitiveParameter] string $password,
        #[SensitiveParameter] string $blob,
    ): string {
        // Strip version byte then split
        $inner = substr($blob, 1);
        $expectedLen = self::BLOB_BYTES - 1;

        if (strlen($inner) !== $expectedLen) {
            throw new RuntimeException(
                sprintf('Invalid password-wrapped blob length: expected %d, got %d.', $expectedLen, strlen($inner)),
            );
        }

        $salt       = substr($inner, 0, self::SALT_BYTES);
        $nonce      = substr($inner, self::SALT_BYTES, self::NONCE_BYTES);
        $ciphertext = substr($inner, self::SALT_BYTES + self::NONCE_BYTES);

        $wrappingKey = $this->derivePasswordWrappingKey($password, $salt);

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

    private function derivePasswordWrappingKey(
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

    // ─────────────────────────────────────────────────────────────────────────
    // Private — Mode 2 helpers
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Wrap a key with a server-derived key (BLAKE2b-HKDF, no Argon2id).
     * Blob: 0x02 || nonce(24) || ciphertext(48) = 73 bytes
     * AD  = userId bytes
     */
    private function wrapWithServerKey(
        #[SensitiveParameter] string $key,
        #[SensitiveParameter] string $appKey,
        string $userId,
    ): string {
        $nonce       = random_bytes(self::NONCE_BYTES);
        $wrappingKey = $this->deriveServerWrappingKey($appKey, $userId);

        try {
            $ct = sodium_crypto_aead_xchacha20poly1305_ietf_encrypt(
                $key, $userId, $nonce, $wrappingKey,
            );
        } finally {
            sodium_memzero($wrappingKey);
        }

        return chr(self::VERSION_SERVER) . $nonce . $ct;
    }

    private function doUnwrapServerBlob(
        #[SensitiveParameter] string $appKey,
        string $userId,
        #[SensitiveParameter] string $blob,
    ): string {
        $inner       = substr($blob, 1);
        $expectedLen = self::SERVER_BLOB_BYTES - 1;

        if (strlen($inner) !== $expectedLen) {
            throw new RuntimeException(
                sprintf('Invalid server-wrapped blob length: expected %d, got %d.', $expectedLen, strlen($inner)),
            );
        }

        $nonce      = substr($inner, 0, self::NONCE_BYTES);
        $ciphertext = substr($inner, self::NONCE_BYTES);

        $wrappingKey = $this->deriveServerWrappingKey($appKey, $userId);

        try {
            $result = sodium_crypto_aead_xchacha20poly1305_ietf_decrypt(
                $ciphertext, $userId, $nonce, $wrappingKey,
            );
        } finally {
            sodium_memzero($wrappingKey);
        }

        if ($result === false) {
            throw new RuntimeException('Failed to unwrap server-wrapped blob: authentication tag mismatch.');
        }

        return $result;
    }

    /**
     * Derive a wrapping key for server-mode blobs.
     *
     * BLAKE2b(key=appKey, msg=userId, outlen=32, personal=HKDF_CONTEXT)
     *
     * This is deterministic from appKey+userId — no salt needed because appKey
     * is already a high-entropy secret (32 random bytes).
     */
    private function deriveServerWrappingKey(
        #[SensitiveParameter] string $appKey,
        string $userId,
    ): string {
        // Ensure appKey is exactly 32 bytes (sodium_crypto_generichash minimum key = 16)
        $key = strlen($appKey) >= SODIUM_CRYPTO_GENERICHASH_KEYBYTES
            ? substr($appKey, 0, SODIUM_CRYPTO_GENERICHASH_KEYBYTES_MAX)
            : sodium_pad($appKey, SODIUM_CRYPTO_GENERICHASH_KEYBYTES);

        return sodium_crypto_generichash(
            self::HKDF_CONTEXT . $userId,
            $key,
            self::WRAPPING_KEY_BYTES,
        );
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Private — shared helpers
    // ─────────────────────────────────────────────────────────────────────────

    private function readVersion(string $blob): int
    {
        if ($blob === '') {
            throw new RuntimeException('Blob is empty.');
        }

        return ord($blob[0]);
    }
}
