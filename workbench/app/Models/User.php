<?php

declare(strict_types=1);

namespace Workbench\App\Models;

use CodeLieutenant\LaravelCrypto\Casts\PasswordDerivedEncrypted;
use CodeLieutenant\LaravelCrypto\Traits\HasUserEncryption;
use Illuminate\Foundation\Auth\User as Authenticatable;

/**
 * @property int         $id
 * @property string      $name
 * @property string      $email
 * @property string      $password
 * @property string|null $encryption_key   Self-contained 88-byte blob
 * @property string|null $secret_note      Encrypted with PasswordDerivedEncrypted cast
 * @property string|null $ssn              Encrypted with PasswordDerivedEncrypted cast
 */
class User extends Authenticatable
{
    use HasUserEncryption;

    protected $table = 'users';

    protected $fillable = ['name', 'email', 'password'];

    protected $hidden = ['password', 'encryption_key'];

    protected function casts(): array
    {
        return [
            'secret_note' => PasswordDerivedEncrypted::class,
            'ssn'         => PasswordDerivedEncrypted::class,
        ];
    }
}

