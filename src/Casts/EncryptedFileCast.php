<?php

declare(strict_types=1);

namespace CodeLieutenant\LaravelCrypto\Casts;

use CodeLieutenant\LaravelCrypto\Support\EncryptedFile;
use Illuminate\Contracts\Database\Eloquent\CastsAttributes;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\Crypt;
use RuntimeException;

/**
 * @implements CastsAttributes<EncryptedFile|null, EncryptedFile|string|null>
 */
class EncryptedFileCast implements CastsAttributes
{
    public function get(Model $model, string $key, mixed $value, array $attributes): ?EncryptedFile
    {
        if ($value === null) {
            return null;
        }

        return new EncryptedFile($value);
    }

    /**
     * @param  EncryptedFile|string|null  $value
     */
    public function set(Model $model, string $key, $value, array $attributes): EncryptedFile|string|null
    {
        if ($value === null) {
            return null;
        }

        if ($value instanceof EncryptedFile) {
            if ($value->isDirty()) {
                $dir = dirname($value->getEncryptedPath());
                if ($dir !== '.' && ! is_dir($dir) && ! mkdir($dir, 0755, true) && ! is_dir($dir)) {
                    throw new RuntimeException(sprintf('Directory "%s" was not created', $dir));
                }
                Crypt::encryptFile($value->getDecryptedPath(), $value->getEncryptedPath());
            }

            return $value->getEncryptedPath();
        }

        return $value;
    }
}
