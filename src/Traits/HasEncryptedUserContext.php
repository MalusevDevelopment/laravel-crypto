<?php

declare(strict_types=1);

namespace CodeLieutenant\LaravelCrypto\Traits;

use CodeLieutenant\LaravelCrypto\Contracts\UserEncryptionContext;
use CodeLieutenant\LaravelCrypto\Encryption\UserKey\SealedJobKey;
use CodeLieutenant\LaravelCrypto\Encryption\UserKey\UserEncrypter;
use Illuminate\Contracts\Foundation\Application;
use RuntimeException;
use SensitiveParameter;
use SodiumException;
use Throwable;

/**
 * Gives a queued job access to the per-user encryption context.
 *
 * ## The problem
 *
 * The UserEncryptionContext is request-scoped.  Queued jobs run outside an
 * HTTP request, so the context is always empty.  Without this trait every
 * UserEncrypted / UserEncryptedJson cast would throw
 * MissingEncryptionContextException inside a job.
 *
 * ## The solution
 *
 * Before dispatching, the caller seals the user key into a SealedJobKey
 * (XSalsa20-Poly1305, random nonce, app-key wrapped).  The sealed key is
 * safe to store in the queue payload — the raw key never appears there.
 *
 * On the worker side, just before handle() runs, the trait unseals the key,
 * loads it into the context, and zeroes the raw bytes.  After handle()
 * returns (or fails), the context is cleared.
 *
 * ## Setup — two lines
 *
 *   class ProcessUserReport implements ShouldQueue
 *   {
 *       use HasEncryptedUserContext;
 *       use Dispatchable, InteractsWithQueue, Queueable, SerializesModels;
 *
 *       public function handle(UserEncrypter $crypt): void
 *       {
 *           // UserEncrypted casts on any model work transparently here
 *           $this->loadEncryptionContext(); // call once, at top of handle()
 *
 *           $user = User::find($this->userId);
 *           echo $user->ssn; // decrypted
 *       }
 *   }
 *
 * ## Dispatching
 *
 *   $sealedKey = SealedJobKey::seal(
 *       $request->user()->currentEncryptionKey(), // raw 32-byte key from context
 *       config('app.key'),
 *   );
 *
 *   // Or use the convenience method if you have the context available:
 *   ProcessUserReport::dispatchWithKey($sealedKey, $userId);
 *
 * @mixin \Illuminate\Contracts\Queue\ShouldQueue
 */
trait HasEncryptedUserContext
{
    /**
     * The sealed user key to carry through the queue.
     *
     * Set this before dispatching:
     *   $job->sealedKey = SealedJobKey::seal($rawKey, $appKey);
     *
     * Or use withUserContext() for a fluent API.
     */
    public ?SealedJobKey $sealedKey = null;

    // ── Fluent factory ────────────────────────────────────────────────────
    /**
     * Attach a sealed user key to this job instance before dispatching.
     *
     * @param  string  $rawUserKey  Raw 32-byte key from UserEncryptionContext::get()
     */
    public function withUserContext(#[SensitiveParameter] string $rawUserKey): static
    {
        $appKey = $this->resolveAppKeyRaw();
        $this->sealedKey = SealedJobKey::seal($rawUserKey, $appKey);

        return $this;
    }

    /**
     * Convenience: create a sealed key directly from the active context.
     *
     * Call this inside a controller / middleware where the context is loaded:
     *
     *   ProcessReport::dispatch($userId)
     *       ->withContextFromRequest(app(UserEncryptionContext::class));
     */
    public function withContextFromRequest(UserEncryptionContext $context): static
    {
        return $this->withUserContext($context->get());
    }

    // ── Job lifecycle ─────────────────────────────────────────────────────
    /**
     * Unseal the key and load it into the container-scoped UserEncryptionContext.
     *
     * Call this at the **very top** of your handle() method, before accessing
     * any UserEncrypted model attributes:
     *
     *   public function handle(): void
     *   {
     *       $this->loadEncryptionContext();
     *       // ... rest of your job logic
     *   }
     *
     * @throws RuntimeException|SodiumException when no sealed key has been attached
     */
    public function loadEncryptionContext(): void
    {
        if ($this->sealedKey === null) {
            throw new RuntimeException(
                static::class.'::loadEncryptionContext() called but no SealedJobKey is set. '.
                'Call withUserContext() or withContextFromRequest() before dispatching.',
            );
        }
        $appKey = $this->resolveAppKeyRaw();
        $rawKey = $this->sealedKey->unseal($appKey);
        try {
            $this->resolveContext()->set($rawKey);
        } finally {
            sodium_memzero($rawKey);
            sodium_memzero($appKey);
        }
    }

    /**
     * Clear the encryption context.
     *
     * Called automatically after handle() returns and in failed().
     * You can call it manually inside handle() if you want to revoke access
     * to the key partway through the job.
     */
    public function clearEncryptionContext(): void
    {
        try {
            $this->resolveContext()->clear();
        } catch (Throwable) {
            // Context may already be clear; ignore.
        }
    }

    /**
     * Called by the queue worker after handle() returns successfully.
     * Overrides the default no-op — always calls the parent if it exists.
     */
    public function tearDown(): void
    {
        $this->clearEncryptionContext();
    }

    /**
     * Called by the queue worker when the job fails.
     * Zero the context so sensitive data does not linger in memory.
     */
    public function failed(Throwable $exception): void
    {
        $this->clearEncryptionContext();
    }

    // ── Private helpers ───────────────────────────────────────────────────
    private function resolveContext(): UserEncryptionContext
    {
        /** @var Application $app */
        $app = app();

        return $app->make(UserEncryptionContext::class);
    }

    private function resolveAppKeyRaw(): string
    {
        $key = (string) config('app.key', '');
        if (str_starts_with($key, 'base64:')) {
            $decoded = base64_decode(substr($key, 7), strict: true);

            return $decoded !== false ? $decoded : $key;
        }

        return $key;
    }
}
