<?php

declare(strict_types=1);

use CodeLieutenant\LaravelCrypto\Contracts\UserEncryptionContext as UserEncryptionContextContract;
use CodeLieutenant\LaravelCrypto\Encryption\UserKey\UserEncryptionContext;
use CodeLieutenant\LaravelCrypto\Encryption\UserKey\UserSecretManager;
use CodeLieutenant\LaravelCrypto\Events\PasswordChanged;
use CodeLieutenant\LaravelCrypto\Exceptions\MissingEncryptionContextException;
use CodeLieutenant\LaravelCrypto\Keys\Loaders\PerUserKeyLoader;
use CodeLieutenant\LaravelCrypto\Listeners\RewrapUserKeyOnPasswordChange;
use CodeLieutenant\LaravelCrypto\Traits\HasUserEncryption;
use Illuminate\Contracts\Auth\Authenticatable;

// ---------------------------------------------------------------------------
// Service-provider bindings
// ---------------------------------------------------------------------------

test('UserEncryptionContext is scoped (same instance within request)', function (): void {
    $a = $this->app->make(UserEncryptionContextContract::class);
    $b = $this->app->make(UserEncryptionContextContract::class);
    expect($a)->toBeInstanceOf(UserEncryptionContext::class)->toBe($b);
});

test('UserSecretManager is singleton', function (): void {
    $a = $this->app->make(UserSecretManager::class);
    $b = $this->app->make(UserSecretManager::class);
    expect($a)->toBeInstanceOf(UserSecretManager::class)->toBe($b);
});

// ---------------------------------------------------------------------------
// PerUserKeyLoader
// ---------------------------------------------------------------------------

test('PerUserKeyLoader delegates getKey() to context', function (): void {
    $ctx = $this->app->make(UserEncryptionContextContract::class);
    $key = str_repeat("\x42", 32);
    $ctx->set($key);
    expect($this->app->make(PerUserKeyLoader::class)->getKey())->toBe($key);
});

test('PerUserKeyLoader throws when context has no key', function (): void {
    expect(fn () => $this->app->make(PerUserKeyLoader::class)->getKey())
        ->toThrow(MissingEncryptionContextException::class);
});

// ---------------------------------------------------------------------------
// PasswordChanged event + listener
// ---------------------------------------------------------------------------

test('RewrapUserKeyOnPasswordChange listener preserves decryptable key', function (): void {
    $mgr = $this->app->make(UserSecretManager::class);
    $result = $mgr->generate('old-password');
    $origKey = $result['key'];

    $user = new class($result['blob']) implements Authenticatable
    {
        use HasUserEncryption;

        public $exists = true;

        private array $attrs;

        public function __construct(string $blob)
        {
            $this->attrs = ['encryption_key' => $blob];
        }

        public function getAttribute(string $k): mixed
        {
            return $this->attrs[$k] ?? null;
        }

        public function setAttribute(string $k, mixed $v): void
        {
            $this->attrs[$k] = $v;
        }

        public function save(array $options = []): bool
        {
            return true;
        }

        public function getAuthIdentifier(): mixed
        {
            return 1;
        }

        public function getAuthIdentifierName(): string
        {
            return 'id';
        }

        public function getAuthPassword(): string
        {
            return '';
        }

        public function getAuthPasswordName(): string
        {
            return 'password';
        }

        public function getRememberToken(): ?string
        {
            return null;
        }

        public function setRememberToken(mixed $v): void {}

        public function getRememberTokenName(): string
        {
            return '';
        }
    };

    (new RewrapUserKeyOnPasswordChange)->handle(
        new PasswordChanged($user, 'old-password', 'new-password'),
    );

    // Old password must no longer work
    expect(fn () => $mgr->unwrap('old-password', $user->getRawEncryptionKeyBlob()))
        ->toThrow(RuntimeException::class);

    // New password must recover the original key
    expect($mgr->unwrap('new-password', $user->getRawEncryptionKeyBlob()))
        ->toBe($origKey);
});
