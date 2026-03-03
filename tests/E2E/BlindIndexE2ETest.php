<?php

declare(strict_types=1);

use CodeLieutenant\LaravelCrypto\Encryption\UserKey\BlindIndex;
use CodeLieutenant\LaravelCrypto\Facades\UserCrypt;
use Illuminate\Foundation\Http\Middleware\VerifyCsrfToken;
use Illuminate\Support\Facades\DB;
use Workbench\App\Models\User;

/*
|--------------------------------------------------------------------------
| Blind index E2E tests
|
| These tests exercise the full HTTP flow:
|   Store encrypted SSN → SSN index written → search by plaintext SSN →
|   exact user found → cross-user isolation verified
|--------------------------------------------------------------------------
*/

// ── Helpers ───────────────────────────────────────────────────────────────

function registerBlindUser(string $email, string $password = 'p@ss!'): array
{
    $response = test()
        ->withoutMiddleware(VerifyCsrfToken::class)
        ->postJson('/register', [
            'name' => 'Blind User',
            'email' => $email,
            'password' => $password,
        ]);

    $response->assertStatus(201);

    return [
        'user' => User::findOrFail($response->json('id')),
        'token' => $response->headers->get('X-Encryption-Token'),
    ];
}

// ── Store + retrieve SSN via cast ──────────────────────────────────────────

test('UserEncryptedWithIndex cast writes ssn_index alongside ciphertext', function (): void {
    ['user' => $user, 'token' => $token] = registerBlindUser('bi1@test.com');

    $this->actingAs($user)
        ->withHeaders(['X-Encryption-Token' => $token])
        ->withoutMiddleware(VerifyCsrfToken::class)
        ->postJson('/profile/secrets', ['ssn' => '123-45-6789'])
        ->assertOk();

    // Raw DB row: SSN column must be ciphertext, ssn_index must be 32 bytes
    $row = DB::table('users')->where('id', $user->id)->first();
    expect($row->ssn)->not->toBe('123-45-6789');                   // encrypted
    expect(strlen($row->ssn_index))->toBe(BlindIndex::INDEX_BYTES);  // 32-byte index written
});

test('SSN decrypts correctly after being stored via UserEncryptedWithIndex cast', function (): void {
    ['user' => $user, 'token' => $token] = registerBlindUser('bi2@test.com');

    $this->actingAs($user)
        ->withHeaders(['X-Encryption-Token' => $token])
        ->withoutMiddleware(VerifyCsrfToken::class)
        ->postJson('/profile/secrets', ['ssn' => '987-65-4321'])
        ->assertOk();

    $decrypted = $this->actingAs($user)
        ->withHeaders(['X-Encryption-Token' => $token])
        ->withoutMiddleware(VerifyCsrfToken::class)
        ->getJson('/profile/secrets')
        ->assertOk()
        ->json('ssn');

    expect($decrypted)->toBe('987-65-4321');
});

// ── whereUserEncrypted scope ──────────────────────────────────────────────

test('whereUserEncrypted scope finds the correct user by SSN without decryption', function (): void {
    ['user' => $user, 'token' => $token] = registerBlindUser('bi3@test.com');

    $this->actingAs($user)
        ->withHeaders(['X-Encryption-Token' => $token])
        ->withoutMiddleware(VerifyCsrfToken::class)
        ->postJson('/profile/secrets', ['ssn' => '111-22-3333'])
        ->assertOk();

    $results = $this->actingAs($user)
        ->withHeaders(['X-Encryption-Token' => $token])
        ->withoutMiddleware(VerifyCsrfToken::class)
        ->getJson('/search-by-ssn?ssn=111-22-3333')
        ->assertOk()
        ->json();

    expect($results)->toHaveCount(1);
    expect($results[0]['id'])->toBe($user->id);
});

test('whereUserEncrypted scope returns empty for non-matching SSN', function (): void {
    ['user' => $user, 'token' => $token] = registerBlindUser('bi4@test.com');

    $this->actingAs($user)
        ->withHeaders(['X-Encryption-Token' => $token])
        ->withoutMiddleware(VerifyCsrfToken::class)
        ->postJson('/profile/secrets', ['ssn' => '444-55-6666'])
        ->assertOk();

    $results = $this->actingAs($user)
        ->withHeaders(['X-Encryption-Token' => $token])
        ->withoutMiddleware(VerifyCsrfToken::class)
        ->getJson('/search-by-ssn?ssn=000-00-0000')
        ->assertOk()
        ->json();

    expect($results)->toHaveCount(0);
});

// ── Normalisation ─────────────────────────────────────────────────────────

test('blind index normalises: search with different casing still finds the record', function (): void {
    ['user' => $user, 'token' => $token] = registerBlindUser('bi5@test.com');

    // Store 'Test Value' — normalised to 'test value' in the index
    $this->actingAs($user)
        ->withHeaders(['X-Encryption-Token' => $token])
        ->withoutMiddleware(VerifyCsrfToken::class)
        ->postJson('/profile/secrets', ['ssn' => 'Test Value'])
        ->assertOk();

    // Search with uppercase + extra spaces — also normalised before lookup
    $results = $this->actingAs($user)
        ->withHeaders(['X-Encryption-Token' => $token])
        ->withoutMiddleware(VerifyCsrfToken::class)
        ->getJson('/search-by-ssn?ssn=TEST+VALUE')
        ->assertOk()
        ->json();

    expect($results)->toHaveCount(1);
});

// ── Cross-user isolation ──────────────────────────────────────────────────

test('same SSN stored by two users produces different blind indexes (per-user isolation)', function (): void {
    ['user' => $userA, 'token' => $tokenA] = registerBlindUser('bi_a@test.com');
    ['user' => $userB, 'token' => $tokenB] = registerBlindUser('bi_b@test.com');

    $ssn = '555-66-7777';

    foreach ([[$userA, $tokenA], [$userB, $tokenB]] as [$u, $t]) {
        $this->actingAs($u)
            ->withHeaders(['X-Encryption-Token' => $t])
            ->withoutMiddleware(VerifyCsrfToken::class)
            ->postJson('/profile/secrets', ['ssn' => $ssn])
            ->assertOk();
    }

    $rowA = DB::table('users')->where('id', $userA->id)->value('ssn_index');
    $rowB = DB::table('users')->where('id', $userB->id)->value('ssn_index');

    // Same SSN, different users → different indexes
    expect($rowA)->not->toBe($rowB);
});

test('user A searching for their SSN does not find user B\'s record', function (): void {
    ['user' => $userA, 'token' => $tokenA] = registerBlindUser('bi_iso_a@test.com');
    ['user' => $userB, 'token' => $tokenB] = registerBlindUser('bi_iso_b@test.com');

    $ssn = '888-99-0000';

    foreach ([[$userA, $tokenA], [$userB, $tokenB]] as [$u, $t]) {
        $this->actingAs($u)
            ->withHeaders(['X-Encryption-Token' => $t])
            ->withoutMiddleware(VerifyCsrfToken::class)
            ->postJson('/profile/secrets', ['ssn' => $ssn])
            ->assertOk();
    }

    // User A searches → finds only their own record
    $results = $this->actingAs($userA)
        ->withHeaders(['X-Encryption-Token' => $tokenA])
        ->withoutMiddleware(VerifyCsrfToken::class)
        ->getJson('/search-by-ssn?ssn='.urlencode($ssn))
        ->assertOk()
        ->json();

    expect($results)->toHaveCount(1);
    expect($results[0]['id'])->toBe($userA->id);
});

// ── UserCrypt facade ──────────────────────────────────────────────────────

test('UserCrypt::blindIndex returns 32-byte binary, same for same inputs', function (): void {
    ['user' => $user, 'token' => $token] = registerBlindUser('bi_facade@test.com');

    // Run inside middleware context via HTTP route
    $r1 = $this->actingAs($user)
        ->withHeaders(['X-Encryption-Token' => $token])
        ->withoutMiddleware(VerifyCsrfToken::class)
        ->postJson('/blind-index', ['value' => 'hello', 'column' => 'ssn'])
        ->assertOk()
        ->json('index');

    $r2 = $this->actingAs($user)
        ->withHeaders(['X-Encryption-Token' => $token])
        ->withoutMiddleware(VerifyCsrfToken::class)
        ->postJson('/blind-index', ['value' => 'hello', 'column' => 'ssn'])
        ->assertOk()
        ->json('index');

    expect($r1)->toBe($r2);
    expect(strlen(base64_decode($r1)))->toBe(BlindIndex::INDEX_BYTES);
});

test('UserCrypt::blindIndex differs per column for same value', function (): void {
    ['user' => $user, 'token' => $token] = registerBlindUser('bi_col@test.com');

    $r1 = $this->actingAs($user)
        ->withHeaders(['X-Encryption-Token' => $token])
        ->withoutMiddleware(VerifyCsrfToken::class)
        ->postJson('/blind-index', ['value' => 'same', 'column' => 'ssn'])
        ->assertOk()
        ->json('index');

    $r2 = $this->actingAs($user)
        ->withHeaders(['X-Encryption-Token' => $token])
        ->withoutMiddleware(VerifyCsrfToken::class)
        ->postJson('/blind-index', ['value' => 'same', 'column' => 'email'])
        ->assertOk()
        ->json('index');

    expect($r1)->not->toBe($r2);
});

// ── Setting SSN to null clears the index ─────────────────────────────────

test('setting ssn to null also clears the blind index', function (): void {
    ['user' => $user, 'token' => $token] = registerBlindUser('bi_null@test.com');

    // Set SSN
    $this->actingAs($user)
        ->withHeaders(['X-Encryption-Token' => $token])
        ->withoutMiddleware(VerifyCsrfToken::class)
        ->postJson('/profile/secrets', ['ssn' => '777-88-9999'])
        ->assertOk();

    // Clear SSN
    $this->actingAs($user)
        ->withHeaders(['X-Encryption-Token' => $token])
        ->withoutMiddleware(VerifyCsrfToken::class)
        ->postJson('/profile/secrets', ['ssn' => null])
        ->assertOk();

    $row = DB::table('users')->where('id', $user->id)->first();
    expect($row->ssn)->toBeNull();
    expect($row->ssn_index)->toBeNull();
});
