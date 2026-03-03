<?php

declare(strict_types=1);

namespace CodeLieutenant\LaravelCrypto\Casts;

use CodeLieutenant\LaravelCrypto\Encryption\UserKey\UserEncrypter;
use Illuminate\Contracts\Database\Eloquent\CastsAttributes;
use Illuminate\Contracts\Encryption\DecryptException;
use Illuminate\Database\Eloquent\Model;
use JsonException;

/**
 * JSON-encrypts a field **and** maintains a blind index on a chosen sub-key,
 * making one field inside the JSON object searchable without decryption.
 *
 * ## Usage
 *
 *   // Migration
 *   $table->text('profile')->nullable();
 *   $table->binary('profile_email_index', length: 32)->nullable()->index();
 *
 *   // Cast — index the 'email' key inside the JSON object
 *   'profile' => UserEncryptedJsonWithIndex::class . ':profile_email_index,email',
 *
 * ## Query
 *
 *   User::where('profile_email_index', UserCrypt::blindIndex('alice@example.com', 'profile'))->first();
 *
 *   // Or via the scope (uses the index column name you passed):
 *   User::whereUserEncrypted('profile', 'alice@example.com', 'profile_email_index')->first();
 *
 * ## Notes
 *
 * - The blind index is computed on the value of `$indexKey` inside the array/object.
 *   If the key is absent or null, the index column is set to null.
 * - See the security note on UserEncryptedWithIndex — blind indexes leak equality.
 */
final readonly class UserEncryptedJsonWithIndex implements CastsAttributes
{
    /**
     * @param  string  $indexColumn  DB column storing the blind index (e.g. 'profile_email_index')
     * @param  string  $indexKey  The JSON key whose value is indexed (e.g. 'email')
     * @param  string  $as  Return type: 'array' (default) or 'object'
     * @param  bool  $normalise  Normalise the indexed value before hashing (default: true)
     * @param  string  $mode  Indexing mode: 'user' (default) or 'global' / 'uniquePerTable'
     * @param  string|null  $context  Comma-separated list of columns to include in the hash
     */
    public function __construct(
        private string $indexColumn,
        private string $indexKey,
        private string $as = 'array',
        private bool $normalise = true,
        private string $mode = 'user',
        private ?string $context = null,
    ) {}

    /**
     * Decrypt and JSON-decode. Returns array or stdClass depending on $as.
     *
     * @return array<array-key, mixed>|\stdClass|null
     */
    public function get(Model $model, string $key, mixed $value, array $attributes): array|\stdClass|null
    {
        if ($value === null) {
            return null;
        }

        $json = app(UserEncrypter::class)->decryptString((string) $value);

        try {
            return json_decode($json, associative: $this->as !== 'object', flags: JSON_THROW_ON_ERROR);
        } catch (JsonException $e) {
            throw new DecryptException(
                message: "Failed to JSON-decode decrypted value for [{$key}]: {$e->getMessage()}",
                previous: $e,
            );
        }
    }

    /**
     * JSON-encode, encrypt, and compute a blind index on one JSON sub-key.
     *
     * @return array<string, string|null>
     */
    public function set(Model $model, string $key, mixed $value, array $attributes): array
    {
        if ($value === null) {
            return [$key => null, $this->indexColumn => null];
        }

        try {
            $json = json_encode($value, flags: JSON_THROW_ON_ERROR | JSON_UNESCAPED_UNICODE);
        } catch (JsonException $e) {
            throw new \Illuminate\Contracts\Encryption\EncryptException(
                message: "Failed to JSON-encode value for [{$key}]: {$e->getMessage()}",
                previous: $e,
            );
        }

        $encrypter = app(UserEncrypter::class);
        $ciphertext = $encrypter->encryptString($json);

        // Derive the blind index from the chosen sub-key inside the JSON value
        $indexValue = $this->extractIndexValue($value);

        $contextValues = [];
        if ($this->context) {
            foreach (explode(',', $this->context) as $column) {
                $contextValues[] = (string) ($attributes[$column] ?? '');
            }
        }

        if ($indexValue !== null) {
            $index = ($this->mode === 'global' || $this->mode === 'uniquePerTable')
                ? $encrypter->globalBlindIndex($indexValue, $key, $this->normalise, $contextValues)
                : $encrypter->blindIndex($indexValue, $key, $this->normalise, $contextValues);
        } else {
            $index = null;
        }

        return [$key => $ciphertext, $this->indexColumn => $index];
    }

    // ─────────────────────────────────────────────────────────────────────────

    private function extractIndexValue(mixed $value): ?string
    {
        if (is_array($value)) {
            $raw = $value[$this->indexKey] ?? null;
        } elseif ($value instanceof \stdClass) {
            $raw = $value->{$this->indexKey} ?? null;
        } else {
            return null;
        }

        return ($raw !== null && $raw !== '') ? (string) $raw : null;
    }
}
