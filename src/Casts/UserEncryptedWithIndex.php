<?php

declare(strict_types=1);

namespace CodeLieutenant\LaravelCrypto\Casts;

use CodeLieutenant\LaravelCrypto\Encryption\UserKey\UserEncrypter;
use Illuminate\Contracts\Database\Eloquent\CastsAttributes;
use Illuminate\Database\Eloquent\Model;

/**
 * Eloquent cast that encrypts/decrypts a field **and** maintains a blind
 * index column so the field remains searchable without decryption.
 *
 * ## Setup
 *
 * 1. Add a `binary(32)` column named `{field}_index` to your migration:
 *
 *    $table->binary('ssn_index', length: 32)->nullable()->index();
 *
 *    Or use the helper in HasUserEncryption:
 *
 *    HasUserEncryption::addBlindIndexColumn($table, 'ssn');
 *
 * 2. Declare the cast with the index column name as argument:
 *
 *    protected function casts(): array
 *    {
 *        return [
 *            'ssn' => UserEncryptedWithIndex::class . ':ssn_index',
 *        ];
 *    }
 *
 * 3. Query by plaintext value:
 *
 *    // Via the scope on HasUserEncryption:
 *    User::whereUserEncrypted('ssn', '123-45-6789')->first();
 *
 *    // Or manually via UserEncrypter:
 *    $idx = UserCrypt::blindIndex('123-45-6789', 'ssn');
 *    User::where('ssn_index', $idx)->first();
 *
 * ## Security note
 *
 * Blind indexes leak equality — an observer with DB read access can tell that
 * two rows hold the same value in a column, but learns nothing about the value
 * itself.  Only use on high-cardinality fields (SSN, email, phone, passport).
 */
final readonly class UserEncryptedWithIndex implements CastsAttributes
{
    /**
     * @param  string  $indexColumn  The DB column that stores the blind index
     *                               (e.g. 'ssn_index')
     * @param  bool  $normalise  Lowercase + trim before hashing (default: true)
     */
    public function __construct(
        private string $indexColumn,
        private bool $normalise = true,
    ) {}

    /**
     * Decrypt the stored ciphertext.  The index column is not returned here —
     * it is only written on set().
     */
    public function get(Model $model, string $key, mixed $value, array $attributes): ?string
    {
        if ($value === null) {
            return null;
        }

        return app(UserEncrypter::class)->decryptString((string) $value);
    }

    /**
     * Encrypt the plaintext and compute a fresh blind index.
     *
     * Returns an array so Eloquent writes both the ciphertext column and the
     * index column in the same UPDATE/INSERT.
     *
     * @return array<string, string|null>
     */
    public function set(Model $model, string $key, mixed $value, array $attributes): array
    {
        if ($value === null) {
            return [
                $key => null,
                $this->indexColumn => null,
            ];
        }

        $encrypter = app(UserEncrypter::class);
        $plaintext = (string) $value;

        return [
            $key => $encrypter->encryptString($plaintext),
            $this->indexColumn => $encrypter->blindIndex($plaintext, $key, $this->normalise),
        ];
    }
}
