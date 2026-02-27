<?php

declare(strict_types=1);

namespace CodeLieutenant\LaravelCrypto\Events;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Foundation\Events\Dispatchable;
use SensitiveParameter;

/**
 * Dispatch this BEFORE hashing the new password so the listener can
 * re-wrap the encryption key with the new plaintext password.
 *
 *   PasswordChanged::dispatch($user, $currentPassword, $newPassword);
 *   $user->password = Hash::make($newPassword);
 *   $user->save();
 */
final class PasswordChanged
{
    use Dispatchable;

    public function __construct(
        public readonly Authenticatable $user,
        #[SensitiveParameter]
        public readonly string $oldPassword,
        #[SensitiveParameter]
        public readonly string $newPassword,
    ) {}
}
