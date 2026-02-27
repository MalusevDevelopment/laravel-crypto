<?php

declare(strict_types=1);

use CodeLieutenant\LaravelCrypto\Encryption\UserKey\BlindIndex;
use CodeLieutenant\LaravelCrypto\Encryption\UserKey\UserEncryptionContext;
use CodeLieutenant\LaravelCrypto\Exceptions\MissingEncryptionContextException;

// ---------------------------------------------------------------------------
// BlindIndex
// ---------------------------------------------------------------------------

describe('BlindIndex', function (): void {
    beforeEach(function (): void {
        $this->ctx   = new UserEncryptionContext;
        $this->key   = random_bytes(SODIUM_CRYPTO_KDF_KEYBYTES); // 32 bytes
        $this->ctx->set($this->key);
        $this->bi    = new BlindIndex($this->ctx);
    });

    afterEach(function (): void {
        $this->ctx->clear();
    });

    test('compute() returns exactly 32 bytes', function (): void {
        $idx = $this->bi->compute('123-45-6789', 'ssn');
        expect(strlen($idx))->toBe(BlindIndex::INDEX_BYTES);
    });

    test('compute() is deterministic — same inputs produce same output', function (): void {
        $a = $this->bi->compute('123-45-6789', 'ssn');
        $b = $this->bi->compute('123-45-6789', 'ssn');
        expect($a)->toBe($b);
    });

    test('compute() is per-user — different user keys produce different indexes', function (): void {
        $ctx2 = new UserEncryptionContext;
        $ctx2->set(random_bytes(32));
        $bi2 = new BlindIndex($ctx2);

        $a = $this->bi->compute('same-value', 'ssn');
        $b = $bi2->compute('same-value', 'ssn');

        expect($a)->not->toBe($b);
        $ctx2->clear();
    });

    test('compute() is per-column — same value in different columns gives different index', function (): void {
        $ssnIdx   = $this->bi->compute('alice@example.com', 'ssn');
        $emailIdx = $this->bi->compute('alice@example.com', 'email');
        expect($ssnIdx)->not->toBe($emailIdx);
    });

    test('compute() normalises by default (case-insensitive, trimmed)', function (): void {
        $a = $this->bi->compute('Alice Smith', 'name');
        $b = $this->bi->compute('  alice smith  ', 'name');
        expect($a)->toBe($b);
    });

    test('compute() with normalise=false is case-sensitive', function (): void {
        $lower = $this->bi->compute('alice', 'name', false);
        $upper = $this->bi->compute('ALICE', 'name', false);
        expect($lower)->not->toBe($upper);
    });

    test('verify() returns true for matching plaintext', function (): void {
        $stored = $this->bi->compute('secret-value', 'field');
        expect($this->bi->verify($stored, 'secret-value', 'field'))->toBeTrue();
    });

    test('verify() returns false for non-matching plaintext', function (): void {
        $stored = $this->bi->compute('secret-value', 'field');
        expect($this->bi->verify($stored, 'other-value', 'field'))->toBeFalse();
    });

    test('verify() returns false for wrong column', function (): void {
        $stored = $this->bi->compute('secret-value', 'ssn');
        expect($this->bi->verify($stored, 'secret-value', 'email'))->toBeFalse();
    });

    test('verify() returns false for wrong-length stored index', function (): void {
        expect($this->bi->verify('tooshort', 'anything', 'col'))->toBeFalse();
    });

    test('compute() throws MissingEncryptionContextException when context is empty', function (): void {
        $emptyCtx = new UserEncryptionContext;
        $bi       = new BlindIndex($emptyCtx);
        expect(fn () => $bi->compute('value', 'col'))->toThrow(MissingEncryptionContextException::class);
    });

    test('column names longer than 8 bytes produce distinct indexes (no truncation collision)', function (): void {
        // Both names share the same first 8 bytes but must still be distinct
        // because the column context is derived via BLAKE2b, not simple truncation.
        $a = $this->bi->compute('v', 'very_long_column_name_a');
        $b = $this->bi->compute('v', 'very_long_column_name_b');
        expect($a)->not->toBe($b);
    });
});

