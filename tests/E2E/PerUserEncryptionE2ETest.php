<?php

declare(strict_types=1);

use CodeLieutenant\LaravelCrypto\Contracts\UserEncryptionContext as UserEncryptionContextContract;
use CodeLieutenant\LaravelCrypto\Encryption\UserKey\UserEncrypter;
use CodeLieutenant\LaravelCrypto\Encryption\UserKey\UserSecretManager;
use CodeLieutenant\LaravelCrypto\Exceptions\MissingEncryptionContextException;
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

    expect($token)->toBeString()->not->toBeEmpty()
        ->and($user->hasUserEncryptionInitialised())->toBeTrue();
});

test('registration stores single encryption_key blob (88 bytes), never plaintext', function (): void {
    ['token' => $token, 'user' => $user] = registerUser('bob@test.com');

    $row = DB::table('users')->where('id', $user->id)->first();
    expect($row->encryption_key)->not->toBeNull()
        ->and(strlen($row->encryption_key))->toBe(UserSecretManager::BLOB_BYTES)
        ->and($row->encryption_key)->not->toContain($token);
});

test('token decodes to a 32-byte key', function (): void {
    ['token' => $token] = registerUser('charlie@test.com');

    $key = app(UserSecretManager::class)->decodeToken($token);
    expect($key)->not->toBeNull()
        ->and(strlen($key))->toBe(UserSecretManager::KEY_BYTES);
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
    expect($row->secret_note)->not->toContain('1234')
        ->and($row->ssn)->not->toContain('123-45-6789');
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
    expect(static fn () => app(UserEncrypter::class)->decryptString($ciphertext))
        ->toThrow(MissingEncryptionContextException::class);
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

// ── Per-user file encryption ──────────────────────────────────────────────

test('per-user file encrypt / decrypt roundtrip via injection', function (): void {
    ['user' => $user, 'token' => $token] = registerUser('fenc1@test.com');

    $plaintext = str_repeat('secret file content for user 🔐 ', 128); // ~4 KB
    $input = tempnam(sys_get_temp_dir(), 'pue_in_');
    $encrypted = tempnam(sys_get_temp_dir(), 'pue_enc_');
    $decrypted = tempnam(sys_get_temp_dir(), 'pue_dec_');
    file_put_contents($input, $plaintext);

    try {
        // Encrypt
        $this->actingAs($user)
            ->withHeaders(['X-Encryption-Token' => $token])
            ->withoutMiddleware(\Illuminate\Foundation\Http\Middleware\VerifyCsrfToken::class)
            ->postJson('/encrypt-file', ['input' => $input, 'output' => $encrypted])
            ->assertOk();

        // The encrypted file must not contain plaintext
        expect(file_get_contents($encrypted))->not->toContain('secret file content');

        // Decrypt
        $this->actingAs($user)
            ->withHeaders(['X-Encryption-Token' => $token])
            ->withoutMiddleware(\Illuminate\Foundation\Http\Middleware\VerifyCsrfToken::class)
            ->postJson('/decrypt-file', ['input' => $encrypted, 'output' => $decrypted])
            ->assertOk();

        expect(file_get_contents($decrypted))->toBe($plaintext);
    } finally {
        @unlink($input);
        @unlink($encrypted);
        @unlink($decrypted);
    }
});

test('per-user file encryption via UserCrypt facade', function (): void {
    ['user' => $user, 'token' => $token] = registerUser('fenc2@test.com');

    $plaintext = 'facade file test 🗄️';
    $input = tempnam(sys_get_temp_dir(), 'pue_fin_');
    $encrypted = tempnam(sys_get_temp_dir(), 'pue_fenc_');
    $decrypted = tempnam(sys_get_temp_dir(), 'pue_fdec_');
    file_put_contents($input, $plaintext);

    try {
        $this->actingAs($user)
            ->withHeaders(['X-Encryption-Token' => $token])
            ->withoutMiddleware(\Illuminate\Foundation\Http\Middleware\VerifyCsrfToken::class)
            ->postJson('/encrypt-file', ['input' => $input, 'output' => $encrypted])
            ->assertOk();

        $this->actingAs($user)
            ->withHeaders(['X-Encryption-Token' => $token])
            ->withoutMiddleware(\Illuminate\Foundation\Http\Middleware\VerifyCsrfToken::class)
            ->postJson('/decrypt-file', ['input' => $encrypted, 'output' => $decrypted])
            ->assertOk();

        expect(file_get_contents($decrypted))->toBe($plaintext);
    } finally {
        @unlink($input);
        @unlink($encrypted);
        @unlink($decrypted);
    }
});

test('file encrypted by user A cannot be decrypted by user B', function (): void {
    ['user' => $userA, 'token' => $tokenA] = registerUser('fenc_a@test.com', 'passA');
    ['user' => $userB, 'token' => $tokenB] = registerUser('fenc_b@test.com', 'passB');

    $input = tempnam(sys_get_temp_dir(), 'pue_xa_');
    $encrypted = tempnam(sys_get_temp_dir(), 'pue_xenc_');
    $decrypted = tempnam(sys_get_temp_dir(), 'pue_xdec_');
    file_put_contents($input, 'user A secret file');

    try {
        $this->actingAs($userA)
            ->withHeaders(['X-Encryption-Token' => $tokenA])
            ->withoutMiddleware(\Illuminate\Foundation\Http\Middleware\VerifyCsrfToken::class)
            ->postJson('/encrypt-file', ['input' => $input, 'output' => $encrypted])
            ->assertOk();

        // User B tries to decrypt — must fail with 500 (DecryptException)
        $this->actingAs($userB)
            ->withHeaders(['X-Encryption-Token' => $tokenB])
            ->withoutMiddleware(\Illuminate\Foundation\Http\Middleware\VerifyCsrfToken::class)
            ->postJson('/decrypt-file', ['input' => $encrypted, 'output' => $decrypted])
            ->assertStatus(500);
    } finally {
        @unlink($input);
        @unlink($encrypted);
        @unlink($decrypted);
    }
});
// ── Backwards compatibility & auto-enrollment ─────────────────────────────

test('user with no encryption_key gets auto-enrolled on first authenticated request', function (): void {
    // Simulate a pre-existing user who was created before per-user encryption
    $user = User::create([
        'name' => 'Legacy User',
        'email' => 'legacy@test.com',
        'password' => \Illuminate\Support\Facades\Hash::make('secret'),
        // encryption_key intentionally omitted — simulates existing users
    ]);
    expect($user->getRawEncryptionKeyBlob())->toBeNull();

    // Make an authenticated request WITHOUT any X-Encryption-Token header
    $response = $this->actingAs($user)
        ->withoutMiddleware(VerifyCsrfToken::class)
        ->postJson('/encrypt-string', ['value' => 'hello legacy']);

    $response->assertOk();

    // The response MUST carry a new token
    $token = $response->headers->get('X-Encryption-Token');
    expect($token)->not->toBeNull()->not->toBeEmpty();

    // The DB must now have a server-wrapped blob
    $user->refresh();
    $mgr = app(UserSecretManager::class);
    expect($user->getRawEncryptionKeyBlob())->not->toBeNull()
        ->and($mgr->isServerWrapped($user->getRawEncryptionKeyBlob()))->toBeTrue();
});

test('auto-enrolled user can decrypt on subsequent request using the returned token', function (): void {
    $user = User::create([
        'name' => 'Auto User',
        'email' => 'auto@test.com',
        'password' => \Illuminate\Support\Facades\Hash::make('secret'),
    ]);

    // First request — no token, auto-enrolls
    $r1 = $this->actingAs($user)
        ->withoutMiddleware(VerifyCsrfToken::class)
        ->postJson('/encrypt-string', ['value' => 'auto secret']);

    $r1->assertOk();
    $token = $r1->headers->get('X-Encryption-Token');
    $ciphertext = $r1->json('ciphertext');
    expect($token)->not->toBeNull();

    // Second request — use the issued token, must decrypt
    $user->refresh();
    $plaintext = $this->actingAs($user)
        ->withHeaders(['X-Encryption-Token' => $token])
        ->withoutMiddleware(VerifyCsrfToken::class)
        ->postJson('/decrypt-string', ['ciphertext' => $ciphertext])
        ->assertOk()
        ->json('plaintext');

    expect($plaintext)->toBe('auto secret');
});

test('BootPerUserEncryption re-derives the same key on repeated no-token requests', function (): void {
    $user = User::create([
        'name' => 'Rederive User',
        'email' => 'rederive@test.com',
        'password' => \Illuminate\Support\Facades\Hash::make('secret'),
    ]);

    // Request 1 — auto-enroll + encrypt
    $r1 = $this->actingAs($user)->withoutMiddleware(VerifyCsrfToken::class)
        ->postJson('/encrypt-string', ['value' => 'persistent value']);
    $ciphertext = $r1->json('ciphertext');
    $token1 = $r1->headers->get('X-Encryption-Token');

    $user->refresh();

    // Request 2 — no token sent (frontend hasn't cached yet), must re-derive
    $r2 = $this->actingAs($user)->withoutMiddleware(VerifyCsrfToken::class)
        ->postJson('/decrypt-string', ['ciphertext' => $ciphertext]);
    $r2->assertOk();
    expect($r2->json('plaintext'))->toBe('persistent value');

    // Both responses carry the same underlying key
    $mgr = app(UserSecretManager::class);
    $token2 = $r2->headers->get('X-Encryption-Token');
    expect($mgr->decodeToken($token2))->toBe($mgr->decodeToken($token1));
});

test('server-wrapped blob is promoted to password-wrapped on next password-login', function (): void {
    $user = User::create([
        'name' => 'Promote User',
        'email' => 'promote@test.com',
        'password' => \Illuminate\Support\Facades\Hash::make('mypassword'),
    ]);

    // Auto-enroll via an unauthenticated-token request
    $this->actingAs($user)->withoutMiddleware(VerifyCsrfToken::class)
        ->postJson('/encrypt-string', ['value' => 'pre-promotion']);

    $user->refresh();
    $mgr = app(UserSecretManager::class);
    expect($mgr->isServerWrapped($user->getRawEncryptionKeyBlob()))->toBeTrue();

    // Login with password — promotes blob to password-wrapped
    $loginResp = $this->withoutMiddleware(VerifyCsrfToken::class)
        ->postJson('/login', ['email' => 'promote@test.com', 'password' => 'mypassword']);
    $loginResp->assertOk();
    $token = $loginResp->headers->get('X-Encryption-Token');
    expect($token)->not->toBeNull();

    $user->refresh();
    expect($mgr->isServerWrapped($user->getRawEncryptionKeyBlob()))->toBeFalse();

    // Data encrypted with the promoted key round-trips correctly
    $ciphertext = $this->actingAs($user)
        ->withHeaders(['X-Encryption-Token' => $token])
        ->withoutMiddleware(VerifyCsrfToken::class)
        ->postJson('/encrypt-string', ['value' => 'after promotion'])
        ->assertOk()->json('ciphertext');

    $plaintext = $this->actingAs($user)
        ->withHeaders(['X-Encryption-Token' => $token])
        ->withoutMiddleware(VerifyCsrfToken::class)
        ->postJson('/decrypt-string', ['ciphertext' => $ciphertext])
        ->assertOk()->json('plaintext');

    expect($plaintext)->toBe('after promotion');
});

test('session-only login: auto-enrolls and issues token on first subsequent request', function (): void {
    User::create([
        'name' => 'Web User',
        'email' => 'web@test.com',
        'password' => \Illuminate\Support\Facades\Hash::make('webpass'),
    ]);

    // Plain session login — no token in response
    $loginResp = $this->withoutMiddleware(VerifyCsrfToken::class)
        ->postJson('/login-session', ['email' => 'web@test.com', 'password' => 'webpass']);
    $loginResp->assertOk();
    expect($loginResp->headers->get('X-Encryption-Token'))->toBeNull();

    // First protected request — auto-enrolls, token in response
    $user = User::where('email', 'web@test.com')->firstOrFail();
    $r = $this->actingAs($user)->withoutMiddleware(VerifyCsrfToken::class)
        ->postJson('/encrypt-string', ['value' => 'web secret']);
    $r->assertOk();
    $token = $r->headers->get('X-Encryption-Token');
    expect($token)->not->toBeNull();

    // Subsequent request with the token works normally
    $user->refresh();
    $plaintext = $this->actingAs($user)
        ->withHeaders(['X-Encryption-Token' => $token])
        ->withoutMiddleware(VerifyCsrfToken::class)
        ->postJson('/decrypt-string', ['ciphertext' => $r->json('ciphertext')])
        ->assertOk()->json('plaintext');
    expect($plaintext)->toBe('web secret');
});

test('PasswordDerivedEncrypted cast returns null gracefully when context is missing and field is null', function (): void {
    // A user without a key accessing a null-valued encrypted field must not throw
    $user = User::create([
        'name' => 'No Key User',
        'email' => 'nokey@test.com',
        'password' => \Illuminate\Support\Facades\Hash::make('pass'),
    ]);

    // No token sent, no blob — field is null in DB
    $response = $this->actingAs($user)
        ->withoutMiddleware(VerifyCsrfToken::class)
        ->getJson('/profile/secrets');

    // Auto-enrolled; null fields return null — no exception
    $response->assertOk();
    expect($response->json('secret_note'))->toBeNull();
    expect($response->json('ssn'))->toBeNull();
});

// ── Cookie transport ──────────────────────────────────────────────────────

test('auto-enroll writes an encrypted HTTP-only enc_token cookie', function (): void {
    $user = \Workbench\App\Models\User::create([
        'name' => 'Cookie User',
        'email' => 'cookie1@test.com',
        'password' => \Illuminate\Support\Facades\Hash::make('pass'),
    ]);

    // No header, no cookie → auto-enroll
    $response = $this->actingAs($user)
        ->withoutMiddleware(VerifyCsrfToken::class)
        ->postJson('/encrypt-string', ['value' => 'cookie test']);

    $response->assertOk();

    // Cookie must be present in the response
    $cookie = $response->headers->getCookies()[0] ?? null;
    expect($cookie)->not->toBeNull();
    expect($cookie->getName())->toBe('enc_token');
    expect($cookie->isHttpOnly())->toBeTrue();
    // Value must be a non-empty string (Laravel-encrypted ciphertext)
    expect($cookie->getValue())->not->toBeEmpty();
    // The raw cookie value must NOT be the plain base64url token
    $mgr = app(UserSecretManager::class);
    expect($mgr->decodeToken($cookie->getValue()))->toBeNull(); // can't decode encrypted value as token
});

test('web client can use enc_token cookie to decrypt on next request', function (): void {
    $user = \Workbench\App\Models\User::create([
        'name' => 'Cookie Round-trip',
        'email' => 'cookie2@test.com',
        'password' => \Illuminate\Support\Facades\Hash::make('pass'),
    ]);

    // Step 1 — auto-enroll (no header, no cookie), get back the cookie
    $encResponse = $this->actingAs($user)
        ->withoutMiddleware(VerifyCsrfToken::class)
        ->postJson('/encrypt-string', ['value' => 'cookie roundtrip']);

    $encResponse->assertOk();
    $ciphertext = $encResponse->json('ciphertext');
    $cookieObj = collect($encResponse->headers->getCookies())->first(fn ($c) => $c->getName() === 'enc_token');
    expect($cookieObj)->not->toBeNull();

    // Step 2 — send the cookie back, no header — must decrypt
    $user->refresh();
    $plaintext = $this->actingAs($user)
        ->withCookies(['enc_token' => $cookieObj->getValue()])
        ->withoutMiddleware(VerifyCsrfToken::class)
        ->postJson('/decrypt-string', ['ciphertext' => $ciphertext])
        ->assertOk()
        ->json('plaintext');

    expect($plaintext)->toBe('cookie roundtrip');
});

test('cookie takes priority over auto-enroll but header takes priority over cookie', function (): void {
    ['user' => $user, 'token' => $headerToken] = registerUser('priority@test.com', 'pass');

    // Build a valid encrypted cookie from the token
    $encrypter = app(\Illuminate\Contracts\Encryption\Encrypter::class);
    $cookieValue = $encrypter->encryptString($headerToken);

    // Request with BOTH header and cookie — header wins
    $ciphertext = $this->actingAs($user)
        ->withHeaders(['X-Encryption-Token' => $headerToken])
        ->withCookies(['enc_token' => $cookieValue])
        ->withoutMiddleware(VerifyCsrfToken::class)
        ->postJson('/encrypt-string', ['value' => 'priority test'])
        ->assertOk()
        ->json('ciphertext');

    // Decrypt using header only — succeeds (same key)
    $plaintext = $this->actingAs($user)
        ->withHeaders(['X-Encryption-Token' => $headerToken])
        ->withoutMiddleware(VerifyCsrfToken::class)
        ->postJson('/decrypt-string', ['ciphertext' => $ciphertext])
        ->assertOk()
        ->json('plaintext');

    expect($plaintext)->toBe('priority test');

    // Decrypt using cookie only — also succeeds (same key, different transport)
    $user->refresh();
    $plaintextCookie = $this->actingAs($user)
        ->withCookies(['enc_token' => $cookieValue])
        ->withoutMiddleware(VerifyCsrfToken::class)
        ->postJson('/decrypt-string', ['ciphertext' => $ciphertext])
        ->assertOk()
        ->json('plaintext');

    expect($plaintextCookie)->toBe('priority test');
});

test('tampered enc_token cookie is silently ignored and falls back to auto-derive', function (): void {
    $user = \Workbench\App\Models\User::create([
        'name' => 'Tamper User',
        'email' => 'tamper@test.com',
        'password' => \Illuminate\Support\Facades\Hash::make('pass'),
    ]);

    // Auto-enroll first so a server-wrapped blob is in the DB
    $this->actingAs($user)
        ->withoutMiddleware(VerifyCsrfToken::class)
        ->postJson('/encrypt-string', ['value' => 'init']);

    $user->refresh();

    // Send a completely bogus cookie — should be silently ignored,
    // middleware falls through to auto-derive and issues a fresh cookie
    $response = $this->actingAs($user)
        ->withCookies(['enc_token' => 'totally-invalid-garbage'])
        ->withoutMiddleware(VerifyCsrfToken::class)
        ->postJson('/encrypt-string', ['value' => 'after tamper']);

    $response->assertOk();

    // A fresh cookie must be in the response
    $freshCookie = collect($response->headers->getCookies())->first(fn ($c) => $c->getName() === 'enc_token');
    expect($freshCookie)->not->toBeNull();
    expect($freshCookie->getValue())->not->toBe('totally-invalid-garbage');
});

test('cookie_encrypt=false stores the raw base64url token in the cookie', function (): void {
    // Override config for this test
    config(['crypto.per_user.cookie_encrypt' => false]);

    $user = \Workbench\App\Models\User::create([
        'name' => 'Unencrypted Cookie',
        'email' => 'rawcookie@test.com',
        'password' => \Illuminate\Support\Facades\Hash::make('pass'),
    ]);

    $response = $this->actingAs($user)
        ->withoutMiddleware(VerifyCsrfToken::class)
        ->postJson('/encrypt-string', ['value' => 'raw cookie value']);

    $response->assertOk();
    $cookie = collect($response->headers->getCookies())->first(fn ($c) => $c->getName() === 'enc_token');
    expect($cookie)->not->toBeNull();

    // With encrypt=false the cookie value IS the raw base64url token
    $mgr = app(UserSecretManager::class);
    expect($mgr->decodeToken($cookie->getValue()))->not->toBeNull();

    // Restore
    config(['crypto.per_user.cookie_encrypt' => true]);
});
