<?php

declare(strict_types=1);

namespace CodeLieutenant\LaravelCrypto\Encryption\UserKey;

use CodeLieutenant\LaravelCrypto\Contracts\UserEncryptionContext as UserEncryptionContextContract;
use CodeLieutenant\LaravelCrypto\Exceptions\MissingEncryptionContextException;
use SensitiveParameter;
use SodiumException;

/**
 * Computes per-user, per-column blind indexes for searchable encrypted fields.
 *
 * ## What is a blind index?
 *
 * A blind index is a deterministic MAC of the plaintext stored alongside the
 * ciphertext.  It enables exact-match queries (WHERE ssn_index = ?) without
 * ever decrypting the table.
 *
 * ## Security properties
 *
 * - **Per-user isolation** — the index key is derived from the user's own
 *   32-byte key.  Two users with the same SSN produce different indexes.
 * - **Per-column isolation** — a separate sub-key is derived for every column
 *   name, so the same value in different columns produces different indexes.
 * - **Key separation** — sub-keys are derived via libsodium's official KDF
 *   (`sodium_crypto_kdf_derive_from_key`), never the raw user key.
 * - **Fixed output** — always 32 bytes, stored as binary in the DB.
 *
 * ## Leakage warning
 *
 * Blind indexes leak **equality**.  An attacker with read access to the DB can
 * tell that two rows contain the same value in the same column for the same user.
 * They learn nothing about the actual value.  Do NOT use blind indexes on
 * low-entropy fields (e.g. gender, boolean flags) — only on high-cardinality
 * values like SSN, email, phone number, passport number.
 *
 * ## KDF derivation
 *
 *   subKey = KDF(masterKey=userKey, id=1, ctx=left8(column_name))
 *   index  = BLAKE2b(plaintext, key=subKey, outlen=32)
 *
 * @see https://doc.libsodium.org/key_derivation
 */
final readonly class BlindIndex
{
    /** Output length of the blind index in bytes. */
    public const int INDEX_BYTES = 32;

    /** KDF sub-key ID (fixed — one sub-key per column name). */
    private const int KDF_SUBKEY_ID = 1;

    public function __construct(
        private UserEncryptionContextContract $context,
    ) {}

    /**
     * Compute a blind index for the given plaintext and column name.
     *
     * @param  string  $value  Plaintext to index (normalised before hashing)
     * @param  string  $column  Column name — used to derive a per-column sub-key
     * @param  bool  $normalise  When true, lowercases and trims the value before
     *                           hashing so that 'Alice' and ' alice ' match.
     * @return string Raw 32-byte binary index — store in a binary(32) column.
     *
     * @throws MissingEncryptionContextException|SodiumException when no user key is loaded
     */
    public function compute(
        #[SensitiveParameter] string $value,
        string $column,
        bool $normalise = true,
    ): string {
        $userKey = $this->context->get();
        $subKey = $this->deriveColumnSubKey($userKey, $column);

        $input = $normalise ? mb_strtolower(trim($value)) : $value;

        return sodium_crypto_generichash($input, $subKey, self::INDEX_BYTES);
    }

    /**
     * Verify that a stored blind index matches the given plaintext.
     * Uses a constant-time comparison to prevent timing attacks.
     */
    public function verify(
        string $storedIndex,
        #[SensitiveParameter] string $value,
        string $column,
        bool $normalise = true,
    ): bool {
        if (strlen($storedIndex) !== self::INDEX_BYTES) {
            return false;
        }

        $computed = $this->compute($value, $column, $normalise);

        return hash_equals($storedIndex, $computed);
    }

    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Derive a per-column sub-key from the user key.
     *
     * The KDF context must be exactly 8 bytes.  We hash the column name with
     * BLAKE2b (minimum output = 16 bytes) and take the first 8 bytes as the
     * context, so any column name — short or arbitrarily long — produces a
     * unique, fixed-length 8-byte context without truncation collisions.
     */
    private function deriveColumnSubKey(string $userKey, string $column): string
    {
        // BLAKE2b minimum output is SODIUM_CRYPTO_GENERICHASH_BYTES_MIN (16).
        // We take the first 8 bytes as the KDF context.
        $hash = sodium_crypto_generichash($column, '', SODIUM_CRYPTO_GENERICHASH_BYTES_MIN);
        $ctx = substr($hash, 0, 8);

        return sodium_crypto_kdf_derive_from_key(
            self::INDEX_BYTES,
            self::KDF_SUBKEY_ID,
            $ctx,
            $userKey,
        );
    }
}
