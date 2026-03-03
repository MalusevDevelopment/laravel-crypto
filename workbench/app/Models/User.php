<?php

declare(strict_types=1);

namespace Workbench\App\Models;

use CodeLieutenant\LaravelCrypto\Casts\UserEncrypted;
use CodeLieutenant\LaravelCrypto\Casts\UserEncryptedJson;
use CodeLieutenant\LaravelCrypto\Casts\UserEncryptedJsonWithIndex;
use CodeLieutenant\LaravelCrypto\Casts\UserEncryptedWithIndex;
use CodeLieutenant\LaravelCrypto\Traits\HasUserEncryption;
use Illuminate\Foundation\Auth\User as Authenticatable;

/**
 * @property int $id
 * @property string $name
 * @property string $email
 * @property string $password
 * @property string|null $encryption_key 89-byte blob
 * @property string|null $secret_note UserEncrypted
 * @property string|null $ssn UserEncryptedWithIndex (decrypted: string)
 * @property string|null $ssn_index Blind index (binary 32 bytes, managed by cast)
 * @property array|null $medical_history UserEncryptedJson (decrypted: array)
 * @property array|null $address UserEncryptedJson ':object' (decrypted: stdClass)
 * @property array|null $profile UserEncryptedJsonWithIndex (decrypted: array)
 * @property string|null $profile_email_index Blind index on profile.email (binary 32 bytes)
 */
class User extends Authenticatable
{
    use HasUserEncryption;

    protected $table = 'users';

    protected $fillable = ['name', 'email', 'password'];

    protected $hidden = ['password', 'encryption_key', 'ssn_index', 'profile_email_index'];

    protected function casts(): array
    {
        return [
            'secret_note' => UserEncrypted::class,
            'ssn' => UserEncryptedWithIndex::class.':ssn_index',
            'medical_history' => UserEncryptedJson::class,
            'address' => UserEncryptedJson::class.':object',
            'profile' => UserEncryptedJsonWithIndex::class.':profile_email_index,email',
        ];
    }
}
