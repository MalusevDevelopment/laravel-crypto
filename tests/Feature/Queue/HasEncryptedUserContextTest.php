<?php

declare(strict_types=1);
use CodeLieutenant\LaravelCrypto\Contracts\UserEncryptionContext;
use CodeLieutenant\LaravelCrypto\Encryption\UserKey\SealedJobKey;
use CodeLieutenant\LaravelCrypto\Traits\HasEncryptedUserContext;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Foundation\Queue\Queueable;

// ── Minimal fake job for testing the trait in isolation ───────────────────
// NOTE: The class is defined at file scope (not inside a describe block)
// so Pest can load it as a named class.
class FakeEncryptedJob implements ShouldQueue
{
    use HasEncryptedUserContext;
    use Queueable;

    public bool $handleRan = false;

    public bool $tearDownRan = false;

    public bool $failedRan = false;

    public ?string $keyDuringHandle = null;

    public function handle(): void
    {
        $this->loadEncryptionContext();
        $this->handleRan = true;
        $this->keyDuringHandle = app(UserEncryptionContext::class)->has() ? 'PRESENT' : 'ABSENT';
        // Simulate the queue worker calling tearDown after handle
        $this->tearDown();
    }

    // Override tearDown to intercept + record, then delegate to the trait
    public function tearDown(): void
    {
        $this->clearEncryptionContext(); // trait logic
        $this->tearDownRan = true;
    }

    // Override failed to intercept + record, then delegate to the trait
    public function failed(\Throwable $e): void
    {
        $this->clearEncryptionContext(); // trait logic
        $this->failedRan = true;
    }
}
// ── Helpers ───────────────────────────────────────────────────────────────
function rawAppKey(): string
{
    $key = (string) config('app.key', '');
    if (str_starts_with($key, 'base64:')) {
        $decoded = base64_decode(substr($key, 7), strict: true);

        return $decoded !== false ? $decoded : $key;
    }

    return $key;
}
// ── Tests ──────────────────────────────────────────────────────────────────
test('loadEncryptionContext() makes the context available inside handle()', function (): void {
    $userKey = random_bytes(SODIUM_CRYPTO_SECRETBOX_KEYBYTES);
    $job = (new FakeEncryptedJob)->withUserContext($userKey);
    $job->handle();
    expect($job->keyDuringHandle)->toBe('PRESENT');
});
test('tearDown() clears the context after handle()', function (): void {
    $userKey = random_bytes(32);
    $job = (new FakeEncryptedJob)->withUserContext($userKey);
    $job->handle();
    expect(app(UserEncryptionContext::class)->has())->toBeFalse();
    expect($job->tearDownRan)->toBeTrue();
});
test('failed() clears the context on job failure', function (): void {
    $userKey = random_bytes(32);
    $job = (new FakeEncryptedJob)->withUserContext($userKey);
    $job->loadEncryptionContext();
    expect(app(UserEncryptionContext::class)->has())->toBeTrue();
    $job->failed(new RuntimeException('simulated failure'));
    expect(app(UserEncryptionContext::class)->has())->toBeFalse();
    expect($job->failedRan)->toBeTrue();
});
test('loadEncryptionContext() throws when no sealedKey is attached', function (): void {
    expect(fn () => (new FakeEncryptedJob)->loadEncryptionContext())->toThrow(RuntimeException::class);
});
test('withUserContext() seals and attaches the key correctly', function (): void {
    $userKey = random_bytes(32);
    $job = (new FakeEncryptedJob)->withUserContext($userKey);
    expect($job->sealedKey)->toBeInstanceOf(SealedJobKey::class);
    $recovered = $job->sealedKey->unseal(rawAppKey());
    expect($recovered)->toBe($userKey);
    sodium_memzero($recovered);
});
test('withContextFromRequest() seals from the active UserEncryptionContext', function (): void {
    $userKey = random_bytes(32);
    $ctx = app(UserEncryptionContext::class);
    $ctx->set($userKey);
    $job = (new FakeEncryptedJob)->withContextFromRequest($ctx);
    expect($job->sealedKey)->toBeInstanceOf(SealedJobKey::class);
    $recovered = $job->sealedKey->unseal(rawAppKey());
    expect($recovered)->toBe($userKey);
    sodium_memzero($recovered);
    $ctx->clear();
});
test('no cross-job key leakage: context is empty between successive jobs', function (): void {
    $keyA = random_bytes(32);
    $keyB = random_bytes(32);
    // Job A runs and clears the context
    $jobA = (new FakeEncryptedJob)->withUserContext($keyA);
    $jobA->handle();
    expect(app(UserEncryptionContext::class)->has())->toBeFalse();
    // Job B loads its own key — must NOT see keyA
    $jobB = (new FakeEncryptedJob)->withUserContext($keyB);
    $jobB->loadEncryptionContext();
    $ctx = app(UserEncryptionContext::class);
    expect($ctx->has())->toBeTrue();
    expect($ctx->get())->toBe($keyB);
    expect($ctx->get())->not->toBe($keyA);
    $ctx->clear();
});
test('SealedJobKey survives PHP serialize/unserialize (queue payload simulation)', function (): void {
    $userKey = random_bytes(32);
    $job = (new FakeEncryptedJob)->withUserContext($userKey);
    /** @var FakeEncryptedJob $deserialized */
    $deserialized = unserialize(serialize($job));
    $deserialized->handle();
    expect($deserialized->keyDuringHandle)->toBe('PRESENT');
    expect($deserialized->tearDownRan)->toBeTrue();
    expect(app(UserEncryptionContext::class)->has())->toBeFalse();
});
test('loadEncryptionContext() throws when sealed under a different app key', function (): void {
    $userKey = random_bytes(32);
    $wrongAppKey = random_bytes(32); // different from the real APP_KEY
    $job = new FakeEncryptedJob;
    $job->sealedKey = SealedJobKey::seal($userKey, $wrongAppKey);
    expect(fn () => $job->loadEncryptionContext())->toThrow(RuntimeException::class);
});
