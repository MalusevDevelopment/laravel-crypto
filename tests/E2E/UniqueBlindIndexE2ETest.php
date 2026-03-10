<?php

declare(strict_types=1);

use Illuminate\Foundation\Http\Middleware\VerifyCsrfToken;
use Illuminate\Support\Facades\DB;
use Workbench\App\Models\User;

/*
|--------------------------------------------------------------------------
| Unique Blind Index E2E Test
|--------------------------------------------------------------------------
|
| Tests unique constraints using blind indexes combined with other columns
| in a full request/response cycle with authentication and middleware.
|
*/

function registerTestUser(string $email, string $password = 'p@ss!'): array
{
    $response = test()
        ->withoutMiddleware(VerifyCsrfToken::class)
        ->postJson('/register', [
            'name' => 'Test User',
            'email' => $email,
            'password' => $password,
        ]);

    $response->assertStatus(201);

    return [
        'user' => User::findOrFail($response->json('id')),
        'token' => $response->headers->get('X-Encryption-Token'),
    ];
}

test('blind index with context ensures uniqueness combined with another column (E2E)', function (): void {
    ['user' => $user, 'token' => $token] = registerTestUser('unique-e2e@test.com');

    $payload = [
        'label' => 'API_KEY',
        'value' => 'secret-123',
    ];

    // 1. First secret creation
    $this->actingAs($user)
        ->withHeaders(['X-Encryption-Token' => $token])
        ->withoutMiddleware(VerifyCsrfToken::class)
        ->postJson('/user-secrets', $payload)
        ->assertStatus(201);

    // 2. Try to create the same secret again (same user, same label, same value)
    // This should fail due to DB unique constraint on [user_id, label, secret_value_index]
    $this->actingAs($user)
        ->withHeaders(['X-Encryption-Token' => $token])
        ->withoutMiddleware(VerifyCsrfToken::class)
        ->postJson('/user-secrets', $payload)
        ->assertStatus(500); // SQLite unique violation throws exception -> 500

    // 3. Different label, same value - should WORK because 'label' is part of unique constraint and context
    $this->actingAs($user)
        ->withHeaders(['X-Encryption-Token' => $token])
        ->withoutMiddleware(VerifyCsrfToken::class)
        ->postJson('/user-secrets', [
            'label' => 'OTHER_KEY',
            'value' => 'secret-123',
        ])
        ->assertStatus(201);

    // 4. Same label, different value - should WORK
    $this->actingAs($user)
        ->withHeaders(['X-Encryption-Token' => $token])
        ->withoutMiddleware(VerifyCsrfToken::class)
        ->postJson('/user-secrets', [
            'label' => 'API_KEY',
            'value' => 'secret-456',
        ])
        ->assertStatus(201);
});

test('searching with context finds the correct record (E2E)', function (): void {
    ['user' => $user, 'token' => $token] = registerTestUser('search-e2e@test.com');

    $this->actingAs($user)
        ->withHeaders(['X-Encryption-Token' => $token])
        ->withoutMiddleware(VerifyCsrfToken::class)
        ->postJson('/user-secrets', [
            'label' => 'API_KEY',
            'value' => 'secret-123',
        ])
        ->assertStatus(201);

    // Search with correct context
    $this->actingAs($user)
        ->withHeaders(['X-Encryption-Token' => $token])
        ->getJson('/user-secrets/search?label=API_KEY&value=secret-123')
        ->assertOk()
        ->assertJsonCount(1)
        ->assertJsonPath('0.label', 'API_KEY');

    // Search with wrong value but same label
    $this->actingAs($user)
        ->withHeaders(['X-Encryption-Token' => $token])
        ->getJson('/user-secrets/search?label=API_KEY&value=wrong')
        ->assertOk()
        ->assertJsonCount(0);

    // Search with correct value but wrong label in search query (so context will be wrong)
    $this->actingAs($user)
        ->withHeaders(['X-Encryption-Token' => $token])
        ->getJson('/user-secrets/search?label=WRONG_LABEL&value=secret-123')
        ->assertOk()
        ->assertJsonCount(0);
});
