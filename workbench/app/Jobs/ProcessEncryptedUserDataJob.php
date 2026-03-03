<?php

declare(strict_types=1);

namespace Workbench\App\Jobs;

use CodeLieutenant\LaravelCrypto\Encryption\UserKey\UserEncrypter;
use CodeLieutenant\LaravelCrypto\Traits\HasEncryptedUserContext;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Foundation\Queue\Queueable;
use Workbench\App\Models\User;

/**
 * Example workbench job that reads and writes UserEncrypted columns.
 * Used exclusively by the feature tests.
 */
final class ProcessEncryptedUserDataJob implements ShouldQueue
{
    use HasEncryptedUserContext;
    use Queueable;

    /** Result stored here so tests can inspect it after sync dispatch. */
    public static string $lastDecryptedSsn = '';

    public static string $lastDecryptedNote = '';

    public static bool $contextWasCleared = false;

    public function __construct(
        public readonly int $userId,
    ) {}

    public function handle(UserEncrypter $crypt): void
    {
        $this->loadEncryptionContext();
        $user = User::findOrFail($this->userId);
        // Accessing UserEncrypted casts works transparently
        self::$lastDecryptedSsn = (string) $user->ssn;
        self::$lastDecryptedNote = (string) $user->secret_note;
        // The context is still active — we can also encrypt new values
        $user->secret_note = 'updated by job';
        $user->save();
        // tearDown() will clear the context after handle() returns
    }

    public function tearDown(): void
    {
        // Delegate to the trait, then record that it ran
        self::$contextWasCleared = true;
    }
}
