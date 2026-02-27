<?php

declare(strict_types=1);

namespace CodeLieutenant\LaravelCrypto\Listeners;

use CodeLieutenant\LaravelCrypto\Events\PasswordChanged;
use CodeLieutenant\LaravelCrypto\Traits\HasUserEncryption;

/**
 * Re-wraps the per-user encryption key under the new password when
 * a PasswordChanged event is dispatched.
 *
 * The user_key itself never changes — all existing encrypted data remains
 * readable after the password change.
 */
final class RewrapUserKeyOnPasswordChange
{
    public function handle(PasswordChanged $event): void
    {
        $user = $event->user;

        if (! method_exists($user, 'rewrapUserEncryption')) {
            return;
        }

        /** @phpstan-ignore-next-line */
        $user->rewrapUserEncryption($event->oldPassword, $event->newPassword);
        /** @phpstan-ignore-next-line */
        $user->save();
    }
}

