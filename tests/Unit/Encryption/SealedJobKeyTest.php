<?php

declare(strict_types=1);
use CodeLieutenant\LaravelCrypto\Encryption\UserKey\SealedJobKey;

describe('SealedJobKey', function (): void {
    function appKey(): string
    {
        // 32-byte raw key matching APP_KEY in tests
        $b64 = config('app.key', 'base64:'.base64_encode(random_bytes(32)));
        if (str_starts_with($b64, 'base64:')) {
            return base64_decode(substr($b64, 7), strict: true);
        }

        return $b64;
    }
    test('BLOB_BYTES constant equals 72', function (): void {
        expect(SealedJobKey::BLOB_BYTES)->toBe(72);
    });
    test('seal() produces a base64 string of 96 characters', function (): void {
        $sealed = SealedJobKey::seal(random_bytes(32), appKey());
        expect(strlen((string) $sealed))->toBe(96);
    });
    test('seal() + unseal() round-trips the raw user key', function (): void {
        $userKey = random_bytes(SODIUM_CRYPTO_SECRETBOX_KEYBYTES);
        $appKey = appKey();
        $sealed = SealedJobKey::seal($userKey, $appKey);
        $opened = $sealed->unseal($appKey);
        expect($opened)->toBe($userKey);
        sodium_memzero($opened);
    });
    test('seal() produces a different blob on each call (random nonce)', function (): void {
        $userKey = random_bytes(32);
        $appKey = appKey();
        $a = (string) SealedJobKey::seal($userKey, $appKey);
        $b = (string) SealedJobKey::seal($userKey, $appKey);
        expect($a)->not->toBe($b);
    });
    test('unseal() throws with the wrong app key', function (): void {
        $userKey = random_bytes(32);
        $sealed = SealedJobKey::seal($userKey, appKey());
        $wrongKey = random_bytes(32); // completely different key
        expect(fn () => $sealed->unseal($wrongKey))->toThrow(RuntimeException::class);
    });
    test('unseal() throws when ciphertext is tampered', function (): void {
        $userKey = random_bytes(32);
        $appKey = appKey();
        $blob = (string) SealedJobKey::seal($userKey, $appKey);
        // Flip a byte in the middle of the base64 payload
        $raw = base64_decode($blob, strict: true);
        $raw[40] = $raw[40] ^ "\xff";
        $tampered = SealedJobKey::fromString(base64_encode($raw));
        expect(fn () => $tampered->unseal($appKey))->toThrow(RuntimeException::class);
    });
    test('fromString() round-trips via __toString()', function (): void {
        $blob = (string) SealedJobKey::seal(random_bytes(32), appKey());
        $copy = SealedJobKey::fromString($blob);
        expect((string) $copy)->toBe($blob);
    });
    test('fromString() throws on wrong-length input', function (): void {
        expect(fn () => SealedJobKey::fromString(base64_encode('tooshort')))->toThrow(RuntimeException::class);
    });
    test('fromString() throws on invalid base64', function (): void {
        expect(fn () => SealedJobKey::fromString('not-valid-base64!!!'))->toThrow(RuntimeException::class);
    });
    test('seal() throws when user key is not 32 bytes', function (): void {
        expect(fn () => SealedJobKey::seal('tooshort', appKey()))->toThrow(RuntimeException::class);
    });
    test('seal() throws when app key is shorter than 32 bytes', function (): void {
        expect(fn () => SealedJobKey::seal(random_bytes(32), 'short'))->toThrow(RuntimeException::class);
    });
    test('PHP serialize/unserialize round-trips correctly (simulates queue serialization)', function (): void {
        $userKey = random_bytes(32);
        $appKey = appKey();
        $sealed = SealedJobKey::seal($userKey, $appKey);
        // Laravel queue serializes jobs with PHP serialize()
        $serialized = serialize($sealed);
        $unserialized = unserialize($serialized);
        $opened = $unserialized->unseal($appKey);
        expect($opened)->toBe($userKey);
        sodium_memzero($opened);
    });
    test('__unserialize() throws on corrupt payload', function (): void {
        expect(function (): void {
            $obj = new \stdClass;
            $obj->blob = base64_encode('corrupt-too-short');
            unserialize(serialize($obj)); // won't be a SealedJobKey but test the logic directly
        })->not->toThrow(\Throwable::class); // stdClass is fine; test SealedJobKey directly below
        // Directly test __unserialize with bad data
        $reflection = new ReflectionClass(SealedJobKey::class);
        $instance = $reflection->newInstanceWithoutConstructor();
        expect(fn () => $instance->__unserialize(['blob' => base64_encode('bad')]))->toThrow(RuntimeException::class);
    });
});
