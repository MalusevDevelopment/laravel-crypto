<?php

declare(strict_types=1);

namespace Workbench\App\Models;

use CodeLieutenant\LaravelCrypto\Casts\UserEncryptedWithIndex;
use CodeLieutenant\LaravelCrypto\Traits\HasUserEncryption;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

class UserSecret extends Model
{
    use HasUserEncryption;

    protected $fillable = ['user_id', 'label', 'secret_value'];

    protected $hidden = ['secret_value_index'];

    protected function casts(): array
    {
        return [
            // Normalise: true, mode: user, context: label
            'secret_value' => UserEncryptedWithIndex::class.':secret_value_index,true,user,label',
        ];
    }

    public function user(): BelongsTo
    {
        return $this->belongsTo(User::class);
    }
}
