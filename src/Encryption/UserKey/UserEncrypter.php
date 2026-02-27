<?php

declare(strict_types=1);

namespace CodeLieutenant\LaravelCrypto\Encryption\UserKey;

use CodeLieutenant\LaravelCrypto\Contracts\FileEncrypter;
use CodeLieutenant\LaravelCrypto\Contracts\UserEncryptionContext as UserEncryptionContextContract;
use CodeLieutenant\LaravelCrypto\Encryption\File\SecretStreamFileEncrypter;
use CodeLieutenant\LaravelCrypto\Exceptions\MissingEncryptionContextException;
use Illuminate\Contracts\Encryption\DecryptException;
use Illuminate\Contracts\Encryption\EncryptException;
use Illuminate\Encryption\Encrypter as LaravelEncrypter;
use SensitiveParameter;
use SodiumException;

/**
 * Primary developer-facing API for per-user encryption.
 *
 * Inject this class (or resolve via the UserCrypt facade) in controllers,
 * jobs, and services that need to encrypt/decrypt data on behalf of the
 * current user.
 *
 * The key is read from the request-scoped UserEncryptionContext — it is
 * never stored on the server; it lives only for the duration of the request.
 *
 * ## Value encryption
 *
 *   $ciphertext = UserCrypt::encryptString($ssn);
 *   $ssn        = UserCrypt::decryptString($ciphertext);
 *
 * ## File encryption (uses the user key as the stream-encryption key)
 *
 *   UserCrypt::encryptFile('/path/to/input.pdf', '/path/to/output.enc');
 *   UserCrypt::decryptFile('/path/to/output.enc', '/path/to/restored.pdf');
 *
 * ## Blind index (searchable encrypted fields)
 *
 *   // Compute a 32-byte binary index for storage:
 *   $index = UserCrypt::blindIndex($ssn, 'ssn');
 *
 *   // Scope query — no decryption needed:
 *   User::whereUserEncrypted('ssn', $searchSsn)->get();
 *
 * The same XChaCha20-Poly1305 secretstream used by Crypt::encryptFile is
 * applied — only the key is swapped for the per-user key from the context.
 */
final readonly class UserEncrypter
{
    public function __construct(
        private UserEncryptionContextContract $context,
        private FileEncrypter $fileEncrypter = new SecretStreamFileEncrypter,
        private ?BlindIndex $blindIndex = null,
    ) {}

    // ── Value encryption ─────────────────────────────────────────────────

    /** @throws MissingEncryptionContextException|EncryptException */
    public function encrypt(mixed $value, bool $serialize = true): string
    {
        return $this->makeEncrypter()->encrypt($value, $serialize);
    }

    /** @throws MissingEncryptionContextException|DecryptException */
    public function decrypt(string $payload, bool $unserialize = true): mixed
    {
        return $this->makeEncrypter()->decrypt($payload, $unserialize);
    }

    /** @throws MissingEncryptionContextException|EncryptException */
    public function encryptString(string $value): string
    {
        return $this->makeEncrypter()->encryptString($value);
    }

    /** @throws MissingEncryptionContextException|DecryptException */
    public function decryptString(string $payload): string
    {
        return $this->makeEncrypter()->decryptString($payload);
    }

    // ── File encryption ──────────────────────────────────────────────────

    /**
     * Encrypt a file using the current user's key.
     *
     * Uses the same SecretStreamFileEncrypter (XChaCha20-Poly1305 secretstream)
     * as Crypt::encryptFile — only the key is the per-user context key.
     *
     * @throws MissingEncryptionContextException when no key is loaded
     * @throws EncryptException on I/O or encryption failure
     */
    public function encryptFile(string $inputFilePath, string $outputFilePath): void
    {
        $key = $this->context->get();
        $this->fileEncrypter->encryptFile($key, $inputFilePath, $outputFilePath);
    }

    /**
     * Decrypt a file that was encrypted with this user's key.
     *
     * @throws MissingEncryptionContextException when no key is loaded
     * @throws DecryptException on I/O or authentication failure
     */
    public function decryptFile(string $inputFilePath, string $outputFilePath): void
    {
        $key = $this->context->get();
        $this->fileEncrypter->decryptFile($key, $inputFilePath, $outputFilePath);
    }

    // ── Blind index ───────────────────────────────────────────────────────

    /**
     * Compute a blind index for a plaintext value and column name.
     *
     * Returns a raw 32-byte binary string — store in a binary(32) column
     * named `{column}_index` (e.g. `ssn_index`).
     *
     * @param  string  $value  The plaintext value to index
     * @param  string  $column  Column name used for per-column key derivation
     * @param  bool  $normalise  Lowercase + trim before hashing (default: true)
     *
     * @throws MissingEncryptionContextException|SodiumException when no key is loaded
     */
    public function blindIndex(
        #[SensitiveParameter] string $value,
        string $column,
        bool $normalise = true,
    ): string {
        return $this->getBlindIndex()->compute($value, $column, $normalise);
    }

    /**
     * Verify that a stored blind index matches a plaintext value.
     * Uses constant-time comparison.
     */
    public function verifyBlindIndex(
        string $storedIndex,
        #[SensitiveParameter] string $value,
        string $column,
        bool $normalise = true,
    ): bool {
        return $this->getBlindIndex()->verify($storedIndex, $value, $column, $normalise);
    }

    // ── Context ───────────────────────────────────────────────────────────

    /** True if a key is loaded for the current request. */
    public function hasContext(): bool
    {
        return $this->context->has();
    }

    // ── Private ───────────────────────────────────────────────────────────

    private function getBlindIndex(): BlindIndex
    {
        return $this->blindIndex ?? new BlindIndex($this->context);
    }

    private function makeEncrypter(): LaravelEncrypter
    {
        $key = $this->context->get();

        return new LaravelEncrypter($key, 'AES-256-CBC');
    }
}
