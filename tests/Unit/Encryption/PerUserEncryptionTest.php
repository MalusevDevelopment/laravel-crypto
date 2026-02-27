<?php

declare(strict_types=1);

use CodeLieutenant\LaravelCrypto\Encryption\UserKey\UserEncryptionContext;
use CodeLieutenant\LaravelCrypto\Encryption\UserKey\UserSecretManager;
use CodeLieutenant\LaravelCrypto\Exceptions\MissingEncryptionContextException;

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

    test('BLOB_BYTES constant equals 88', function (): void {
        expect(UserSecretManager::BLOB_BYTES)->toBe(88);
    });

    test('generate() returns key (32 bytes) and blob (88 bytes)', function (): void {
        $result = $this->mgr->generate('password');
        expect(strlen($result['key']))->toBe(UserSecretManager::KEY_BYTES);
        expect(strlen($result['blob']))->toBe(UserSecretManager::BLOB_BYTES);
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
        $result  = $this->mgr->generate('password');
        $blob    = $result['blob'];
        // Flip a byte in the salt region (first 16 bytes)
        $tampered    = $blob;
        $tampered[0] = $tampered[0] === "\x00" ? "\x01" : "\x00";

        expect(fn () => $this->mgr->unwrap('password', $tampered))
            ->toThrow(RuntimeException::class);
    });

    test('tampered nonce in blob fails MAC (AD hardening)', function (): void {
        $result  = $this->mgr->generate('password');
        $blob    = $result['blob'];
        // Flip a byte in the nonce region (bytes 16–39)
        $tampered     = $blob;
        $tampered[16] = $tampered[16] === "\x00" ? "\x01" : "\x00";

        expect(fn () => $this->mgr->unwrap('password', $tampered))
            ->toThrow(RuntimeException::class);
    });

    // ── Rewrap ────────────────────────────────────────────────────────────

    test('rewrap() preserves the original key', function (): void {
        $result  = $this->mgr->generate('old');
        $origKey = $result['key'];
        $newBlob = $this->mgr->rewrap('old', 'new', $result['blob']);
        expect($this->mgr->unwrap('new', $newBlob))->toBe($origKey);
    });

    test('rewrap() produces a new blob (fresh salt+nonce)', function (): void {
        $result  = $this->mgr->generate('old');
        $newBlob = $this->mgr->rewrap('old', 'new', $result['blob']);
        expect($newBlob)->not->toBe($result['blob']);
        expect(strlen($newBlob))->toBe(UserSecretManager::BLOB_BYTES);
    });

    test('old password no longer works after rewrap', function (): void {
        $result  = $this->mgr->generate('old');
        $newBlob = $this->mgr->rewrap('old', 'new', $result['blob']);
        expect(fn () => $this->mgr->unwrap('old', $newBlob))
            ->toThrow(RuntimeException::class);
    });

    // ── Token encoding ────────────────────────────────────────────────────

    test('encodeToken / decodeToken roundtrip', function (): void {
        $key   = random_bytes(UserSecretManager::KEY_BYTES);
        $token = $this->mgr->encodeToken($key);
        expect($this->mgr->decodeToken($token))->toBe($key);
    });

    test('decodeToken returns null for empty string', function (): void {
        expect($this->mgr->decodeToken(''))->toBeNull();
    });

    test('decodeToken returns null for wrong-length token', function (): void {
        expect($this->mgr->decodeToken(base64_encode(random_bytes(10))))->toBeNull();
    });
});

