<?php

declare(strict_types=1);

namespace CodeLieutenant\LaravelCrypto\Encryption\UserKey;

use RuntimeException;
use SensitiveParameter;

/**
 * A serializable envelope that carries a per-user encryption key safely
 * through the Laravel queue.
 *
 * ## How it works
 *
 * When a job is dispatched, the caller seals the user's raw 32-byte key
 * under the application key using sodium_crypto_secretbox (XSalsa20-Poly1305).
 * The resulting blob — nonce(24) || ciphertext+MAC(48) = 72 raw bytes, 96
 * base64 characters — is serialized into the queue payload.
 *
 * The raw user key NEVER appears in the queue payload.  The app key is
 * available on every worker node (APP_KEY), so the worker unseals the
 * envelope just before the job's handle() method runs.
 *
 * ## Security properties
 *
 * - Poly1305 MAC authenticated: tampering causes unseal() to throw.
 * - Random nonce per seal: same key dispatched twice -> different ciphertext.
 * - HasEncryptedUserContext memzeroes the raw key immediately after loading.
 * - On job completion or failure the context is cleared and zeroed.
 *
 * ## Wire format
 *
 *   base64( nonce[24] || secretbox(userKey[32], nonce, appKey)[48] )
 *   Total raw = 72 bytes -> base64 = 96 characters
 *
 * @see HasEncryptedUserContext
 */
final class SealedJobKey implements \Stringable
{
    /** Total byte length of the raw (pre-base64) blob. */
    public const int BLOB_BYTES =
        SODIUM_CRYPTO_SECRETBOX_NONCEBYTES  // 24
        + SODIUM_CRYPTO_SECRETBOX_KEYBYTES  // 32 (plaintext key)
        + SODIUM_CRYPTO_SECRETBOX_MACBYTES;

    // 16 (Poly1305 tag) = 72 total
    private function __construct(
        /** Base64-encoded nonce || secretbox(userKey). */
        private string $blob,
    ) {}

    // ── Factory ───────────────────────────────────────────────────────────
    /**
     * Seal a raw 32-byte user key under the given app key.
     *
     * @param  string  $rawUserKey  Raw 32-byte per-user key
     * @param  string  $appKey  Raw 32-byte application key (APP_KEY decoded)
     */
    public static function seal(
        #[SensitiveParameter] string $rawUserKey,
        #[SensitiveParameter] string $appKey,
    ): self {
        if (strlen($rawUserKey) !== SODIUM_CRYPTO_SECRETBOX_KEYBYTES) {
            throw new RuntimeException(sprintf(
                'SealedJobKey: user key must be %d bytes, got %d.',
                SODIUM_CRYPTO_SECRETBOX_KEYBYTES,
                strlen($rawUserKey),
            ));
        }
        if (strlen($appKey) < SODIUM_CRYPTO_SECRETBOX_KEYBYTES) {
            throw new RuntimeException(sprintf(
                'SealedJobKey: app key must be at least %d bytes, got %d.',
                SODIUM_CRYPTO_SECRETBOX_KEYBYTES,
                strlen($appKey),
            ));
        }
        $nonce = random_bytes(SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
        $sealed = sodium_crypto_secretbox(
            $rawUserKey,
            $nonce,
            substr($appKey, 0, SODIUM_CRYPTO_SECRETBOX_KEYBYTES),
        );

        return new self(base64_encode($nonce.$sealed));
    }

    /**
     * Reconstruct from a previously serialized blob string.
     */
    public static function fromString(string $blob): self
    {
        $raw = base64_decode($blob, strict: true);
        if ($raw === false || strlen($raw) !== self::BLOB_BYTES) {
            throw new RuntimeException(sprintf(
                'SealedJobKey: invalid blob. Expected %d raw bytes after base64 decode.',
                self::BLOB_BYTES,
            ));
        }

        return new self($blob);
    }

    // ── Unsealing ─────────────────────────────────────────────────────────
    /**
     * Unseal and return the raw 32-byte user key.
     *
     * The caller MUST call sodium_memzero() on the returned string
     * immediately after loading it into the context.
     *
     * @param  string  $appKey  Raw 32-byte application key
     * @return string Raw 32-byte user key
     *
     * @throws RuntimeException when MAC verification fails (tampered payload or wrong app key)
     */
    public function unseal(#[SensitiveParameter] string $appKey): string
    {
        $raw = base64_decode($this->blob, strict: true);
        $nonce = substr($raw, 0, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
        $box = substr($raw, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
        $opened = sodium_crypto_secretbox_open(
            $box,
            $nonce,
            substr($appKey, 0, SODIUM_CRYPTO_SECRETBOX_KEYBYTES),
        );
        if ($opened === false) {
            throw new RuntimeException(
                'SealedJobKey: authentication failed — payload may have been tampered '.
                'with or the wrong APP_KEY was used.',
            );
        }

        return $opened;
    }

    // ── Serialization (queue transport) ───────────────────────────────────
    public function __serialize(): array
    {
        return ['blob' => $this->blob];
    }

    public function __unserialize(array $data): void
    {
        $raw = base64_decode($data['blob'] ?? '', strict: true);
        if ($raw === false || strlen($raw) !== self::BLOB_BYTES) {
            throw new RuntimeException('SealedJobKey: corrupt serialized payload.');
        }
        $this->blob = $data['blob'];
    }

    public function __toString(): string
    {
        return $this->blob;
    }

    public function __destruct()
    {
        if (isset($this->blob) && $this->blob !== '') {
            sodium_memzero($this->blob);
        }
    }
}
