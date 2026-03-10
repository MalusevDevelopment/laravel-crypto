<?php

declare(strict_types=1);

namespace CodeLieutenant\LaravelCrypto\Casts;

use CodeLieutenant\LaravelCrypto\Encryption\UserKey\UserEncrypter;
use Illuminate\Contracts\Database\Eloquent\CastsAttributes;
use Illuminate\Contracts\Encryption\DecryptException;
use Illuminate\Contracts\Encryption\EncryptException;
use Illuminate\Database\Eloquent\Model;
use JsonException;
use stdClass;

/**
 * Eloquent cast that JSON-serializes a value, encrypts the JSON string with the
 * per-user key, and reverses the process transparently on read.
 *
 * The entire JSON blob is treated as a single opaque ciphertext — no individual
 * keys inside the array are visible in the database.
 *
 * ## Usage
 *
 *   protected function casts(): array
 *   {
 *       return [
 *           // Returns an associative array on get()
 *           'medical_history' => UserEncryptedJson::class,
 *
 *           // Returns a stdClass on get()
 *           'address' => UserEncryptedJson::class . ':object',
 *
 *           // Works with UserEncryptedWithIndex too (searchable + JSON)
 *           'profile' => UserEncryptedJsonWithIndex::class . ':profile_index',
 *       ];
 *   }
 *
 * ## Storing
 *
 *   $user->medical_history = ['blood_type' => 'O+', 'allergies' => ['penicillin']];
 *   $user->address = ['street' => '123 Main St', 'city' => 'Springfield'];
 *   $user->save();
 *
 * ## Reading
 *
 *   $history = $user->medical_history; // → array
 *   $address = $user->address;         // → array  (or stdClass with ':object')
 *
 * ## Null safety
 *
 *   A null value in the DB returns null on get(). Setting null stores null.
 *
 * ## Context requirement
 *
 *   The X-Encryption-Token header (or enc_token cookie) must be present on any
 *   request that reads or writes these fields, or MissingEncryptionContextException
 *   is thrown. When using the BootPerUserEncryption middleware this is automatic.
 */
final readonly class UserEncryptedJson implements CastsAttributes
{
    /**
     * @param  string  $as  Return type on get(): 'array' (default) or 'object' (stdClass)
     */
    public function __construct(
        private string $as = 'array',
    ) {}

    /**
     * Decrypt the stored ciphertext and JSON-decode it.
     *
     * @return array<array-key, mixed>|stdClass|null
     *
     * @throws DecryptException when the ciphertext is tampered or the wrong key is used
     */
    public function get(Model $model, string $key, mixed $value, array $attributes): array|stdClass|null
    {
        if ($value === null) {
            return null;
        }

        $json = app(UserEncrypter::class)->decryptString((string) $value);

        try {
            $decoded = json_decode($json, associative: $this->as !== 'object', flags: JSON_THROW_ON_ERROR);
        } catch (JsonException $e) {
            throw new DecryptException(
                message: "Failed to JSON-decode decrypted value for [{$key}]: {$e->getMessage()}",
                previous: $e,
            );
        }

        return $decoded;
    }

    /**
     * JSON-encode the value and encrypt it.
     *
     * @param  array<array-key, mixed>|stdClass|string|null  $value
     *
     * @throws EncryptException on encryption failure
     */
    public function set(Model $model, string $key, mixed $value, array $attributes): ?string
    {
        if ($value === null) {
            return null;
        }

        try {
            $json = json_encode($value, flags: JSON_THROW_ON_ERROR | JSON_UNESCAPED_UNICODE);
        } catch (JsonException $e) {
            throw new EncryptException(
                message: "Failed to JSON-encode value for [{$key}]: {$e->getMessage()}",
                previous: $e,
            );
        }

        return app(UserEncrypter::class)->encryptString($json);
    }
}
