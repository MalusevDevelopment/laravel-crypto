<?php

declare(strict_types=1);

namespace Workbench\App\Models;

use CodeLieutenant\LaravelCrypto\Casts\UserEncrypted;
use CodeLieutenant\LaravelCrypto\Casts\UserEncryptedWithIndex;
use CodeLieutenant\LaravelCrypto\Traits\HasUserEncryption;
use Illuminate\Foundation\Auth\User as Authenticatable;

/**
 * @property int $id
 * @property string $name
 * @property string $email
 * @property string $password
 * @property string|null $encryption_key Self-contained 89-byte blob
 * @property string|null $secret_note Encrypted with UserEncrypted cast
 * @property string|null $ssn Encrypted + blind-indexed with UserEncryptedWithIndex cast
 * @property string|null $ssn_index Blind index for SSN (binary 32 bytes, managed by cast)
 */
class User extends Authenticatable
{
    use HasUserEncryption;

    protected $table = 'users';

    protected $fillable = ['name', 'email', 'password'];

    protected $hidden = ['password', 'encryption_key', 'ssn_index'];

    protected function casts(): array
    {
        return [
            'secret_note' => UserEncrypted::class,
            // ssn_index is written automatically by this cast
            'ssn' => UserEncryptedWithIndex::class.':ssn_index',
        ];
    }
}
