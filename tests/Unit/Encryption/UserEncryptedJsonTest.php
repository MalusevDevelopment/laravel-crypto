<?php

declare(strict_types=1);

use CodeLieutenant\LaravelCrypto\Casts\UserEncryptedJson;
use CodeLieutenant\LaravelCrypto\Casts\UserEncryptedJsonWithIndex;
use CodeLieutenant\LaravelCrypto\Encryption\UserKey\UserEncrypter;
use CodeLieutenant\LaravelCrypto\Encryption\UserKey\UserEncryptionContext;
use Illuminate\Contracts\Encryption\DecryptException;
use Illuminate\Database\Eloquent\Model;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeContextAndEncrypter(): array
{
    $ctx = new UserEncryptionContext;
    $ctx->set(random_bytes(SODIUM_CRYPTO_KDF_KEYBYTES));

    // Bind into the container so app(UserEncrypter::class) resolves correctly
    app()->instance(
        \CodeLieutenant\LaravelCrypto\Contracts\UserEncryptionContext::class,
        $ctx,
    );

    return ['ctx' => $ctx, 'encrypter' => app(UserEncrypter::class)];
}

function fakeModel(): Model
{
    return new class extends Model
    {
        protected $table = 'users';
    };
}

// ---------------------------------------------------------------------------
// UserEncryptedJson
// ---------------------------------------------------------------------------

describe('UserEncryptedJson', function (): void {
    afterEach(function (): void {
        // clear context between tests so no key leaks
        try {
            app(\CodeLieutenant\LaravelCrypto\Contracts\UserEncryptionContext::class)->clear();
        } catch (\Throwable) {
        }
    });

    test('set() stores ciphertext, not the raw JSON', function (): void {
        ['ctx' => $ctx] = makeContextAndEncrypter();
        $cast = new UserEncryptedJson;
        $model = fakeModel();
        $data = ['blood_type' => 'O+', 'allergies' => ['penicillin']];

        $stored = $cast->set($model, 'medical_history', $data, []);

        expect($stored)->not->toContain('blood_type')
            ->and($stored)->not->toContain('O+');
        $ctx->clear();
    });

    test('get() returns the original array', function (): void {
        ['ctx' => $ctx] = makeContextAndEncrypter();
        $cast = new UserEncryptedJson;
        $model = fakeModel();
        $data = ['blood_type' => 'O+', 'allergies' => ['penicillin']];

        $stored = $cast->set($model, 'medical_history', $data, []);
        $restored = $cast->get($model, 'medical_history', $stored, []);

        expect($restored)->toBe($data);
        $ctx->clear();
    });

    test("get() returns stdClass when cast is ':object'", function (): void {
        ['ctx' => $ctx] = makeContextAndEncrypter();
        $cast = new UserEncryptedJson('object');
        $model = fakeModel();
        $data = ['street' => '123 Main St', 'city' => 'Springfield'];

        $stored = $cast->set($model, 'address', $data, []);
        $restored = $cast->get($model, 'address', $stored, []);

        expect($restored)->toBeInstanceOf(stdClass::class)
            ->and($restored->street)->toBe('123 Main St')
            ->and($restored->city)->toBe('Springfield');
        $ctx->clear();
    });

    test('get() returns null for null DB value', function (): void {
        makeContextAndEncrypter();
        $cast = new UserEncryptedJson;
        $model = fakeModel();

        expect($cast->get($model, 'medical_history', null, []))->toBeNull();
    });

    test('set() returns null for null input', function (): void {
        makeContextAndEncrypter();
        $cast = new UserEncryptedJson;
        $model = fakeModel();

        expect($cast->set($model, 'medical_history', null, []))->toBeNull();
    });

    test('deeply nested arrays round-trip correctly', function (): void {
        ['ctx' => $ctx] = makeContextAndEncrypter();
        $cast = new UserEncryptedJson;
        $model = fakeModel();
        $data = [
            'visits' => [
                ['date' => '2024-01-01', 'notes' => ['temperature' => 37.2, 'bp' => '120/80']],
                ['date' => '2024-06-15', 'notes' => ['temperature' => 36.8, 'bp' => '118/76']],
            ],
            'medications' => ['aspirin', 'metformin'],
        ];

        $stored = $cast->set($model, 'data', $data, []);
        $restored = $cast->get($model, 'data', $stored, []);

        expect($restored)->toBe($data);
        $ctx->clear();
    });

    test('ciphertext differs between two encryptions of the same data (random IV)', function (): void {
        ['ctx' => $ctx] = makeContextAndEncrypter();
        $cast = new UserEncryptedJson;
        $model = fakeModel();
        $data = ['key' => 'value'];

        $a = $cast->set($model, 'field', $data, []);
        $b = $cast->set($model, 'field', $data, []);

        expect($a)->not->toBe($b); // different nonces
        $ctx->clear();
    });

    test('get() throws DecryptException when ciphertext is tampered', function (): void {
        ['ctx' => $ctx] = makeContextAndEncrypter();
        $cast = new UserEncryptedJson;
        $model = fakeModel();

        $stored = $cast->set($model, 'field', ['k' => 'v'], []);
        $tampered = substr_replace((string) $stored, 'XXXX', 10, 4);

        expect(fn () => $cast->get($model, 'field', $tampered, []))
            ->toThrow(DecryptException::class);
        $ctx->clear();
    });

    test('get() throws DecryptException when decrypted value is not valid JSON', function (): void {
        // Encrypt raw non-JSON and feed it to the JSON cast
        ['ctx' => $ctx] = makeContextAndEncrypter();
        $encrypter = app(UserEncrypter::class);
        $notJson = $encrypter->encryptString('not valid json {{');

        $cast = new UserEncryptedJson;
        $model = fakeModel();

        expect(fn () => $cast->get($model, 'field', $notJson, []))
            ->toThrow(DecryptException::class);
        $ctx->clear();
    });

    test('integers, booleans, and unicode survive round-trip', function (): void {
        ['ctx' => $ctx] = makeContextAndEncrypter();
        $cast = new UserEncryptedJson;
        $model = fakeModel();
        $data = ['count' => 42, 'active' => true, 'name' => 'こんにちは', 'ratio' => 3.14];

        $restored = $cast->get($model, 'f', $cast->set($model, 'f', $data, []), []);

        expect($restored)->toBe($data);
        $ctx->clear();
    });
});

// ---------------------------------------------------------------------------
// UserEncryptedJsonWithIndex
// ---------------------------------------------------------------------------

describe('UserEncryptedJsonWithIndex', function (): void {
    afterEach(function (): void {
        try {
            app(\CodeLieutenant\LaravelCrypto\Contracts\UserEncryptionContext::class)->clear();
        } catch (\Throwable) {
        }
    });

    test('set() returns ciphertext + blind index for the chosen sub-key', function (): void {
        ['ctx' => $ctx] = makeContextAndEncrypter();
        $cast = new UserEncryptedJsonWithIndex('profile_email_index', 'email');
        $model = fakeModel();
        $data = ['email' => 'alice@example.com', 'name' => 'Alice'];

        $result = $cast->set($model, 'profile', $data, []);

        expect($result)->toBeArray()->toHaveKeys(['profile', 'profile_email_index']);
        expect(strlen($result['profile_email_index']))->toBe(\CodeLieutenant\LaravelCrypto\Encryption\UserKey\BlindIndex::INDEX_BYTES);
        $ctx->clear();
    });

    test('get() returns the original array', function (): void {
        ['ctx' => $ctx] = makeContextAndEncrypter();
        $cast = new UserEncryptedJsonWithIndex('profile_email_index', 'email');
        $model = fakeModel();
        $data = ['email' => 'alice@example.com', 'name' => 'Alice'];

        $result = $cast->set($model, 'profile', $data, []);
        $restored = $cast->get($model, 'profile', $result['profile'], []);

        expect($restored)->toBe($data);
        $ctx->clear();
    });

    test('blind index is deterministic for the same sub-key value', function (): void {
        ['ctx' => $ctx] = makeContextAndEncrypter();
        $cast = new UserEncryptedJsonWithIndex('profile_email_index', 'email');
        $model = fakeModel();
        $data = ['email' => 'bob@example.com', 'role' => 'admin'];

        $r1 = $cast->set($model, 'profile', $data, []);
        $r2 = $cast->set($model, 'profile', $data, []);

        expect($r1['profile_email_index'])->toBe($r2['profile_email_index']);
        $ctx->clear();
    });

    test('blind index is null when the indexed sub-key is absent', function (): void {
        ['ctx' => $ctx] = makeContextAndEncrypter();
        $cast = new UserEncryptedJsonWithIndex('profile_email_index', 'email');
        $model = fakeModel();

        $result = $cast->set($model, 'profile', ['name' => 'No Email'], []);

        expect($result['profile_email_index'])->toBeNull();
        $ctx->clear();
    });

    test('set() returns nulls for both columns when value is null', function (): void {
        makeContextAndEncrypter();
        $cast = new UserEncryptedJsonWithIndex('profile_email_index', 'email');
        $model = fakeModel();

        $result = $cast->set($model, 'profile', null, []);

        expect($result)->toBe(['profile' => null, 'profile_email_index' => null]);
    });

    test("get() returns stdClass when cast is ':object'", function (): void {
        ['ctx' => $ctx] = makeContextAndEncrypter();
        $cast = new UserEncryptedJsonWithIndex('idx', 'email', 'object');
        $model = fakeModel();
        $data = ['email' => 'test@test.com', 'x' => 1];

        $result = $cast->set($model, 'field', $data, []);
        $restored = $cast->get($model, 'field', $result['field'], []);

        expect($restored)->toBeInstanceOf(stdClass::class);
        expect($restored->email)->toBe('test@test.com');
        $ctx->clear();
    });

    test('blind index changes when the indexed sub-key value changes', function (): void {
        ['ctx' => $ctx] = makeContextAndEncrypter();
        $cast = new UserEncryptedJsonWithIndex('profile_email_index', 'email');
        $model = fakeModel();

        $r1 = $cast->set($model, 'profile', ['email' => 'a@a.com'], []);
        $r2 = $cast->set($model, 'profile', ['email' => 'b@b.com'], []);

        expect($r1['profile_email_index'])->not->toBe($r2['profile_email_index']);
        $ctx->clear();
    });

    test('stdClass input also extracts the index sub-key', function (): void {
        ['ctx' => $ctx] = makeContextAndEncrypter();
        $cast = new UserEncryptedJsonWithIndex('profile_email_index', 'email');
        $model = fakeModel();
        $obj = (object) ['email' => 'obj@example.com', 'name' => 'Obj'];

        $result = $cast->set($model, 'profile', $obj, []);

        expect($result['profile_email_index'])->not->toBeNull();
        expect(strlen($result['profile_email_index']))->toBe(\CodeLieutenant\LaravelCrypto\Encryption\UserKey\BlindIndex::INDEX_BYTES);
        $ctx->clear();
    });
});
