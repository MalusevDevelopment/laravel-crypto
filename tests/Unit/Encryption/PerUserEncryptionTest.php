<?php

declare(strict_types=1);

use CodeLieutenant\LaravelCrypto\Encryption\UserKey\UserEncrypter;
use CodeLieutenant\LaravelCrypto\Encryption\UserKey\UserEncryptionContext;
use CodeLieutenant\LaravelCrypto\Encryption\UserKey\UserSecretManager;
use CodeLieutenant\LaravelCrypto\Exceptions\MissingEncryptionContextException;
use Illuminate\Contracts\Encryption\DecryptException;

// ---------------------------------------------------------------------------
// UserEncryptionContext
// ---------------------------------------------------------------------------

describe('UserEncryptionContext', function (): void {
    test('has() returns false before set()', function (): void {
        expect((new UserEncryptionContext)->has())->toBeFalse();
    });

    test('has() returns true after set()', function (): void {
        $ctx = new UserEncryptionContext;
        $ctx->set(str_repeat("\x42", 32));
        expect($ctx->has())->toBeTrue();
    });

    test('get() returns the key that was set', function (): void {
        $ctx = new UserEncryptionContext;
        $key = str_repeat("\x42", 32);
        $ctx->set($key);
        expect($ctx->get())->toBe($key);
    });

    test('get() throws MissingEncryptionContextException when empty', function (): void {
        expect(fn () => (new UserEncryptionContext)->get())
            ->toThrow(MissingEncryptionContextException::class);
    });

    test('clear() zeroes key and sets has() to false', function (): void {
        $ctx = new UserEncryptionContext;
        $ctx->set(str_repeat("\xAB", 32));
        $ctx->clear();
        expect($ctx->has())->toBeFalse();
        expect(fn () => $ctx->get())->toThrow(MissingEncryptionContextException::class);
    });

    test('set() overwrites a previous key', function (): void {
        $ctx = new UserEncryptionContext;
        $ctx->set(str_repeat("\x11", 32));
        $ctx->set(str_repeat("\x22", 32));
        expect($ctx->get())->toBe(str_repeat("\x22", 32));
    });
});

// ---------------------------------------------------------------------------
// UserSecretManager
// ---------------------------------------------------------------------------

describe('UserSecretManager', function (): void {
    beforeEach(function (): void {
        $this->mgr = new UserSecretManager(
            opsLimit: SODIUM_CRYPTO_PWHASH_OPSLIMIT_INTERACTIVE,
            memLimit: SODIUM_CRYPTO_PWHASH_MEMLIMIT_INTERACTIVE,
        );
    });

    test('BLOB_BYTES constant equals 89', function (): void {
        expect(UserSecretManager::BLOB_BYTES)->toBe(89);
    });

    test('SERVER_BLOB_BYTES constant equals 73', function (): void {
        expect(UserSecretManager::SERVER_BLOB_BYTES)->toBe(73);
    });

    test('generate() returns key (32 bytes) and blob (89 bytes)', function (): void {
        $result = $this->mgr->generate('password');
        expect(strlen($result['key']))->toBe(UserSecretManager::KEY_BYTES)
            ->and(strlen($result['blob']))->toBe(UserSecretManager::BLOB_BYTES);
    });

    test('generate() blob has version byte 0x01', function (): void {
        $result = $this->mgr->generate('password');
        expect(UserSecretManager::VERSION_PASSWORD)->toBe(0x01)
            ->and($this->mgr->blobVersion($result['blob']))->toBe(UserSecretManager::VERSION_PASSWORD);
    });

    test('generate() produces different blobs for same password (random salt+nonce)', function (): void {
        $a = $this->mgr->generate('password');
        $b = $this->mgr->generate('password');
        expect($a['blob'])->not->toBe($b['blob']);
    });

    test('unwrap() recovers the key produced by generate()', function (): void {
        $result = $this->mgr->generate('secret');
        expect($this->mgr->unwrap('secret', $result['blob']))->toBe($result['key']);
    });

    test('unwrap() throws on wrong password', function (): void {
        $result = $this->mgr->generate('correct');
        expect(fn () => $this->mgr->unwrap('wrong', $result['blob']))
            ->toThrow(RuntimeException::class);
    });

    test('unwrap() throws on truncated blob', function (): void {
        expect(fn () => $this->mgr->unwrap('pass', str_repeat("\x00", 40)))
            ->toThrow(RuntimeException::class);
    });

    // ── AD hardening ──────────────────────────────────────────────────────

    test('tampered salt in blob fails MAC (AD hardening)', function (): void {
        $result = $this->mgr->generate('password');
        $blob = $result['blob'];
        // Salt starts at byte 1 (after version byte) — flip byte at offset 1
        $tampered = $blob;
        $tampered[1] = $tampered[1] === "\x00" ? "\x01" : "\x00";

        expect(fn () => $this->mgr->unwrap('password', $tampered))
            ->toThrow(RuntimeException::class);
    });

    test('tampered nonce in blob fails MAC (AD hardening)', function (): void {
        $result = $this->mgr->generate('password');
        $blob = $result['blob'];
        // Nonce starts at byte 17 (1 version + 16 salt) — flip byte at offset 17
        $tampered = $blob;
        $tampered[17] = $tampered[17] === "\x00" ? "\x01" : "\x00";

        expect(fn () => $this->mgr->unwrap('password', $tampered))
            ->toThrow(RuntimeException::class);
    });

    // ── Rewrap ────────────────────────────────────────────────────────────

    test('rewrap() preserves the original key', function (): void {
        $result = $this->mgr->generate('old');
        $origKey = $result['key'];
        $newBlob = $this->mgr->rewrap('old', 'new', $result['blob']);
        expect($this->mgr->unwrap('new', $newBlob))->toBe($origKey);
    });

    test('rewrap() produces a new blob (fresh salt+nonce)', function (): void {
        $result = $this->mgr->generate('old');
        $newBlob = $this->mgr->rewrap('old', 'new', $result['blob']);
        expect($newBlob)->not->toBe($result['blob'])
            ->and(strlen($newBlob))->toBe(UserSecretManager::BLOB_BYTES);
    });

    test('old password no longer works after rewrap', function (): void {
        $result = $this->mgr->generate('old');
        $newBlob = $this->mgr->rewrap('old', 'new', $result['blob']);
        expect(fn () => $this->mgr->unwrap('old', $newBlob))
            ->toThrow(RuntimeException::class);
    });

    // ── Token encoding ────────────────────────────────────────────────────

    test('encodeToken / decodeToken roundtrip', function (): void {
        $key = random_bytes(UserSecretManager::KEY_BYTES);
        $token = $this->mgr->encodeToken($key);
        expect($this->mgr->decodeToken($token))->toBe($key);
    });

    test('decodeToken returns null for empty string', function (): void {
        expect($this->mgr->decodeToken(''))->toBeNull();
    });

    test('decodeToken returns null for wrong-length token', function (): void {
        expect($this->mgr->decodeToken(base64_encode(random_bytes(10))))->toBeNull();
    });

    // ── Server-wrap (Mode 2) ──────────────────────────────────────────────

    test('generateServerWrapped() returns key (32) and blob (73 bytes) with version 0x02', function (): void {
        $appKey = random_bytes(32);
        $result = $this->mgr->generateServerWrapped($appKey, 'user-42');
        expect(strlen($result['key']))->toBe(UserSecretManager::KEY_BYTES)
            ->and(strlen($result['blob']))->toBe(UserSecretManager::SERVER_BLOB_BYTES)
            ->and($this->mgr->blobVersion($result['blob']))->toBe(UserSecretManager::VERSION_SERVER);
    });

    test('unwrapServerBlob() recovers the key produced by generateServerWrapped()', function (): void {
        $appKey = random_bytes(32);
        $result = $this->mgr->generateServerWrapped($appKey, 'uid-1');
        expect($this->mgr->unwrapServerBlob($appKey, 'uid-1', $result['blob']))->toBe($result['key']);
    });

    test('unwrapServerBlob() fails for wrong userId (AD mismatch)', function (): void {
        $appKey = random_bytes(32);
        $result = $this->mgr->generateServerWrapped($appKey, 'uid-correct');
        expect(fn () => $this->mgr->unwrapServerBlob($appKey, 'uid-wrong', $result['blob']))
            ->toThrow(RuntimeException::class);
    });

    test('unwrapServerBlob() fails for wrong appKey', function (): void {
        $appKey = random_bytes(32);
        $result = $this->mgr->generateServerWrapped($appKey, 'uid-1');
        expect(fn () => $this->mgr->unwrapServerBlob(random_bytes(32), 'uid-1', $result['blob']))
            ->toThrow(RuntimeException::class);
    });

    test('isServerWrapped() distinguishes blob versions', function (): void {
        $pwBlob = $this->mgr->generate('pw')['blob'];
        $srvBlob = $this->mgr->generateServerWrapped(random_bytes(32), 'u')['blob'];
        expect($this->mgr->isServerWrapped($srvBlob))->toBeTrue()
            ->and($this->mgr->isServerWrapped($pwBlob))->toBeFalse();
    });

    test('rewrapServerToPassword() preserves the key and produces password-wrapped blob', function (): void {
        $appKey = random_bytes(32);
        $result = $this->mgr->generateServerWrapped($appKey, 'uid-promote');
        $origKey = $result['key'];

        $promoted = $this->mgr->rewrapServerToPassword($appKey, 'uid-promote', $result['blob'], 'newpass');
        expect($this->mgr->blobVersion($promoted))->toBe(UserSecretManager::VERSION_PASSWORD)
            ->and($this->mgr->unwrap('newpass', $promoted))->toBe($origKey);
    });

    test('unwrapAny() handles both blob versions', function (): void {
        $appKey = random_bytes(32);
        $pwRes = $this->mgr->generate('mypass');
        $srvRes = $this->mgr->generateServerWrapped($appKey, 'uid-any');

        expect($this->mgr->unwrapAny($pwRes['blob'], password: 'mypass'))->toBe($pwRes['key'])
            ->and($this->mgr->unwrapAny($srvRes['blob'], appKey: $appKey, userId: 'uid-any'))->toBe($srvRes['key']);
    });
});

// ---------------------------------------------------------------------------
// UserEncrypter — file encryption
// ---------------------------------------------------------------------------

describe('UserEncrypter file encryption', function (): void {
    beforeEach(function (): void {
        $this->ctx = new UserEncryptionContext;
        $this->encrypter = new UserEncrypter($this->ctx);

        // Use the user key (32 bytes) — valid for XChaCha20-Poly1305 secretstream
        $this->key = random_bytes(SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_KEYBYTES);
        $this->ctx->set($this->key);
    });

    afterEach(function (): void {
        $this->ctx->clear();
    });

    test('encryptFile / decryptFile roundtrip preserves content', function (): void {
        $plaintext = str_repeat('per-user file secret 🔐 ', 64); // ~1.5 KB
        $input = tempnam(sys_get_temp_dir(), 'pu_in_');
        $encrypted = tempnam(sys_get_temp_dir(), 'pu_enc_');
        $decrypted = tempnam(sys_get_temp_dir(), 'pu_dec_');

        file_put_contents($input, $plaintext);

        try {
            $this->encrypter->encryptFile($input, $encrypted);
            expect(file_get_contents($encrypted))->not->toContain('per-user file secret');

            $this->encrypter->decryptFile($encrypted, $decrypted);
            expect(file_get_contents($decrypted))->toBe($plaintext);
        } finally {
            @unlink($input);
            @unlink($encrypted);
            @unlink($decrypted);
        }
    });

    test('encryptFile produces different output on each call (random header)', function (): void {
        $input = tempnam(sys_get_temp_dir(), 'pu_ri_');
        $enc1 = tempnam(sys_get_temp_dir(), 'pu_e1_');
        $enc2 = tempnam(sys_get_temp_dir(), 'pu_e2_');
        file_put_contents($input, 'same content');

        try {
            $this->encrypter->encryptFile($input, $enc1);
            $this->encrypter->encryptFile($input, $enc2);
            expect(file_get_contents($enc1))->not->toBe(file_get_contents($enc2));
        } finally {
            @unlink($input);
            @unlink($enc1);
            @unlink($enc2);
        }
    });

    test('decryptFile fails with a different key (wrong user)', function (): void {
        $input = tempnam(sys_get_temp_dir(), 'pu_wi_');
        $encrypted = tempnam(sys_get_temp_dir(), 'pu_we_');
        $decrypted = tempnam(sys_get_temp_dir(), 'pu_wd_');
        file_put_contents($input, 'user A secret');

        try {
            $this->encrypter->encryptFile($input, $encrypted);

            // Swap in a different key (simulating a different user's context)
            $wrongCtx = new UserEncryptionContext;
            $wrongCtx->set(random_bytes(SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_KEYBYTES));
            $wrongEncrypter = new UserEncrypter($wrongCtx);

            expect(fn () => $wrongEncrypter->decryptFile($encrypted, $decrypted))
                ->toThrow(DecryptException::class);
        } finally {
            @unlink($input);
            @unlink($encrypted);
            @unlink($decrypted);
            isset($wrongCtx) && $wrongCtx->clear();
        }
    });

    test('encryptFile throws MissingEncryptionContextException when context is empty', function (): void {
        $emptyCtx = new UserEncryptionContext;
        $noKeyEncrypter = new UserEncrypter($emptyCtx);
        $tmp = tempnam(sys_get_temp_dir(), 'pu_nt_');
        file_put_contents($tmp, 'x');

        try {
            expect(static fn () => $noKeyEncrypter->encryptFile($tmp, $tmp.'.enc'))
                ->toThrow(MissingEncryptionContextException::class);
        } finally {
            @unlink($tmp);
            @unlink($tmp.'.enc');
        }
    });
});
