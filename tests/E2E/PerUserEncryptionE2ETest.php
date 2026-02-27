<?php

declare(strict_types=1);

use CodeLieutenant\LaravelCrypto\Contracts\UserEncryptionContext as UserEncryptionContextContract;
use CodeLieutenant\LaravelCrypto\Encryption\UserKey\UserEncrypter;
use CodeLieutenant\LaravelCrypto\Encryption\UserKey\UserSecretManager;
use Illuminate\Foundation\Http\Middleware\VerifyCsrfToken;
use Illuminate\Support\Facades\DB;
use Workbench\App\Models\User;

/*
|--------------------------------------------------------------------------
| End-to-end per-user encryption tests
|
| These tests exercise the complete flow through real HTTP routes, a real
| in-memory SQLite database, and the workbench User model.
|
|   Registration → token issued
|   → secrets stored encrypted
|   → secrets decrypted on read
|   → password change → new token issued
|   → data still readable with new token
|   → old password can no longer unwrap the key
|--------------------------------------------------------------------------
*/

// ── Helpers ───────────────────────────────────────────────────────────────

function registerUser(string $email = 'alice@example.com', string $password = 'p@ssw0rd!'): array
{
    $response = test()
        ->withoutMiddleware(VerifyCsrfToken::class)
        ->postJson('/register', [
            'name' => 'Test User',
            'email' => $email,
            'password' => $password,
        ]);

    $response->assertStatus(201);
    $token = $response->headers->get('X-Encryption-Token');
    expect($token)->not->toBeNull()->not->toBeEmpty();

    return [
        'user' => User::findOrFail($response->json('id')),
        'token' => $token,
    ];
}

function loginUser(string $email, string $password): array
{
    $response = test()
        ->withoutMiddleware(VerifyCsrfToken::class)
        ->postJson('/login', ['email' => $email, 'password' => $password]);

    $response->assertOk();
    $token = $response->headers->get('X-Encryption-Token');
    expect($token)->not->toBeNull();

    return [
        'user' => User::where('email', $email)->firstOrFail(),
        'token' => $token,
    ];
}

// ── Registration ──────────────────────────────────────────────────────────

test('registration returns X-Encryption-Token header', function (): void {
    ['token' => $token, 'user' => $user] = registerUser();

    expect($token)->toBeString()->not->toBeEmpty();
    expect($user->hasUserEncryptionInitialised())->toBeTrue();
});

test('registration stores single encryption_key blob (88 bytes), never plaintext', function (): void {
    ['token' => $token, 'user' => $user] = registerUser('bob@test.com');

    $row = DB::table('users')->where('id', $user->id)->first();
    expect($row->encryption_key)->not->toBeNull();
    expect(strlen($row->encryption_key))->toBe(UserSecretManager::BLOB_BYTES);
    expect($row->encryption_key)->not->toContain($token);
});

test('token decodes to a 32-byte key', function (): void {
    ['token' => $token] = registerUser('charlie@test.com');

    $key = app(UserSecretManager::class)->decodeToken($token);
    expect($key)->not->toBeNull();
    expect(strlen($key))->toBe(UserSecretManager::KEY_BYTES);
});

// ── Login ─────────────────────────────────────────────────────────────────

test('login returns a token that decodes to the same key as registration', function (): void {
    ['token' => $regToken] = registerUser('dave@test.com', 'secret123');
    ['token' => $loginToken] = loginUser('dave@test.com', 'secret123');

    $mgr = app(UserSecretManager::class);
    expect($mgr->decodeToken($loginToken))->toBe($mgr->decodeToken($regToken));
});

test('login with wrong password returns 401', function (): void {
    registerUser('eve@test.com', 'correcthorse');

    $this->withoutMiddleware(VerifyCsrfToken::class)
        ->postJson('/login', ['email' => 'eve@test.com', 'password' => 'wrongbattery'])
        ->assertStatus(401);
});

// ── PasswordDerivedEncrypted cast ─────────────────────────────────────────

test('encrypted fields are not stored in plaintext', function (): void {
    ['user' => $user, 'token' => $token] = registerUser('frank@test.com');

    $this->actingAs($user)
        ->withHeaders(['X-Encryption-Token' => $token])
        ->withoutMiddleware(VerifyCsrfToken::class)
        ->postJson('/profile/secrets', [
            'secret_note' => 'My bank PIN is 1234',
            'ssn' => '123-45-6789',
        ])
        ->assertOk();

    $row = DB::table('users')->where('id', $user->id)->first();
    expect($row->secret_note)->not->toContain('1234');
    expect($row->ssn)->not->toContain('123-45-6789');
});

test('encrypted fields round-trip correctly', function (): void {
    ['user' => $user, 'token' => $token] = registerUser('grace@test.com');

    $this->actingAs($user)
        ->withHeaders(['X-Encryption-Token' => $token])
        ->withoutMiddleware(VerifyCsrfToken::class)
        ->postJson('/profile/secrets', ['secret_note' => 'Launch code: 00000000', 'ssn' => '987-65-4321']);

    $this->actingAs($user)
        ->withHeaders(['X-Encryption-Token' => $token])
        ->withoutMiddleware(VerifyCsrfToken::class)
        ->getJson('/profile/secrets')
        ->assertOk()
        ->assertJson(['secret_note' => 'Launch code: 00000000', 'ssn' => '987-65-4321']);
});

test('decrypting without a context key throws MissingEncryptionContextException', function (): void {
    ['user' => $user, 'token' => $token] = registerUser('henry@test.com');

    // Encrypt something with the real key
    $ciphertext = $this->actingAs($user)
        ->withHeaders(['X-Encryption-Token' => $token])
        ->withoutMiddleware(VerifyCsrfToken::class)
        ->postJson('/encrypt-string', ['value' => 'sensitive'])
        ->assertOk()
        ->json('ciphertext');

    // Clear context so it has no key loaded
    app(UserEncryptionContextContract::class)->clear();

    // Direct decryption without a loaded key must throw
    expect(fn () => app(UserEncrypter::class)->decryptString($ciphertext))
        ->toThrow(\CodeLieutenant\LaravelCrypto\Exceptions\MissingEncryptionContextException::class);
});

// ── UserEncrypter injection ───────────────────────────────────────────────

test('UserEncrypter encrypt/decrypt roundtrip via injection', function (): void {
    ['user' => $user, 'token' => $token] = registerUser('iris@test.com');

    $ciphertext = $this->actingAs($user)
        ->withHeaders(['X-Encryption-Token' => $token])
        ->withoutMiddleware(VerifyCsrfToken::class)
        ->postJson('/encrypt', ['value' => ['nested' => 'data', 'count' => 42]])
        ->assertOk()
        ->json('ciphertext');

    expect($ciphertext)->toBeString()->not->toContain('nested');

    $this->actingAs($user)
        ->withHeaders(['X-Encryption-Token' => $token])
        ->withoutMiddleware(VerifyCsrfToken::class)
        ->postJson('/decrypt', ['ciphertext' => $ciphertext])
        ->assertOk()
        ->assertJson(['plaintext' => ['nested' => 'data', 'count' => 42]]);
});

// ── UserCrypt facade ──────────────────────────────────────────────────────

test('UserCrypt facade encryptString / decryptString roundtrip', function (): void {
    ['user' => $user, 'token' => $token] = registerUser('judy@test.com');

    $ciphertext = $this->actingAs($user)
        ->withHeaders(['X-Encryption-Token' => $token])
        ->withoutMiddleware(VerifyCsrfToken::class)
        ->postJson('/encrypt-string', ['value' => 'hello façade 🔐'])
        ->assertOk()
        ->json('ciphertext');

    $this->actingAs($user)
        ->withHeaders(['X-Encryption-Token' => $token])
        ->withoutMiddleware(VerifyCsrfToken::class)
        ->postJson('/decrypt-string', ['ciphertext' => $ciphertext])
        ->assertOk()
        ->assertJson(['plaintext' => 'hello façade 🔐']);
});

// ── Key isolation between users ───────────────────────────────────────────

test('user A token cannot decrypt user B ciphertext', function (): void {
    ['user' => $userA, 'token' => $tokenA] = registerUser('alice2@test.com', 'alicepass');
    ['user' => $userB, 'token' => $tokenB] = registerUser('bob2@test.com', 'bobpass');

    $ciphertext = $this->actingAs($userA)
        ->withHeaders(['X-Encryption-Token' => $tokenA])
        ->withoutMiddleware(VerifyCsrfToken::class)
        ->postJson('/encrypt-string', ['value' => 'alice secret'])
        ->json('ciphertext');

    $this->actingAs($userB)
        ->withHeaders(['X-Encryption-Token' => $tokenB])
        ->withoutMiddleware(VerifyCsrfToken::class)
        ->postJson('/decrypt-string', ['ciphertext' => $ciphertext])
        ->assertStatus(500);
});

// ── Password change ───────────────────────────────────────────────────────

test('password change: new token has same underlying key, old data still readable', function (): void {
    ['user' => $user, 'token' => $oldToken] = registerUser('kate@test.com', 'oldpass');

    $this->actingAs($user)
        ->withHeaders(['X-Encryption-Token' => $oldToken])
        ->withoutMiddleware(VerifyCsrfToken::class)
        ->postJson('/profile/secrets', ['secret_note' => 'Persistent secret', 'ssn' => '000-00-0001']);

    $newToken = $this->actingAs($user)
        ->withHeaders(['X-Encryption-Token' => $oldToken])
        ->withoutMiddleware(VerifyCsrfToken::class)
        ->postJson('/change-password', [
            'current_password' => 'oldpass',
            'new_password' => 'newpass',
        ])
        ->assertOk()
        ->headers->get('X-Encryption-Token');

    expect($newToken)->not->toBeNull();

    // Underlying key is the same — only the wrapping changed (so the token encodes identically)
    $mgr = app(UserSecretManager::class);
    expect($mgr->decodeToken($newToken))->toBe($mgr->decodeToken($oldToken));

    // Existing encrypted data is still readable with the new token
    $user->refresh();
    $this->actingAs($user)
        ->withHeaders(['X-Encryption-Token' => $newToken])
        ->withoutMiddleware(VerifyCsrfToken::class)
        ->getJson('/profile/secrets')
        ->assertOk()
        ->assertJson(['secret_note' => 'Persistent secret', 'ssn' => '000-00-0001']);
});

test('old password cannot unwrap the key after password change', function (): void {
    ['user' => $user, 'token' => $token] = registerUser('lena@test.com', 'oldpassword');

    $this->actingAs($user)
        ->withHeaders(['X-Encryption-Token' => $token])
        ->withoutMiddleware(VerifyCsrfToken::class)
        ->postJson('/change-password', [
            'current_password' => 'oldpassword',
            'new_password' => 'newpassword',
        ])
        ->assertOk();

    $user->refresh();

    expect(fn () => app(UserSecretManager::class)->unwrap('oldpassword', $user->getRawEncryptionKeyBlob()))
        ->toThrow(RuntimeException::class);
});

// ── UserEncrypter container binding ──────────────────────────────────────

test('UserEncrypter::hasContext() is false without middleware', function (): void {
    expect(app(UserEncrypter::class)->hasContext())->toBeFalse();
});

test('UserEncrypter::hasContext() is true after context is populated', function (): void {
    $ctx = app(UserEncryptionContextContract::class);
    $ctx->set(str_repeat("\x42", 32));

    expect(app(UserEncrypter::class)->hasContext())->toBeTrue();

    $ctx->clear();
});
