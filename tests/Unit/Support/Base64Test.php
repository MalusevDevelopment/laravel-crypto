<?php

declare(strict_types=1);

use CodeLieutenant\LaravelCrypto\Support\Base64;

it('encodes binary data', function (): void {
    $data = random_bytes(32);

    expect(Base64::encode($data))->toBe(base64_encode($data))
        ->and(Base64::encodeNoPadding($data))->toBe(rtrim(base64_encode($data), '='))
        ->and(Base64::decode(base64_encode($data)))->toBe($data)
        ->and(Base64::urlEncode($data))->toBe(strtr(base64_encode($data), '+/', '-_'))
        ->and(Base64::urlEncodeNoPadding($data))->toBe(rtrim(strtr(base64_encode($data), '+/', '-_'), '='))
        ->and(Base64::urlDecode(strtr(base64_encode($data), '+/', '-_')))->toBe($data);
});

it('constant time encodes', function (): void {
    $data = random_bytes(32);

    expect(Base64::constantEncode($data))->toBe(sodium_bin2base64($data, SODIUM_BASE64_VARIANT_ORIGINAL))
        ->and(Base64::constantEncodeNoPadding($data))->toBe(sodium_bin2base64($data, SODIUM_BASE64_VARIANT_ORIGINAL_NO_PADDING))
        ->and(Base64::constantDecode(Base64::constantEncode($data)))->toBe($data)
        ->and(Base64::constantUrlEncode($data))->toBe(sodium_bin2base64($data, SODIUM_BASE64_VARIANT_URLSAFE))
        ->and(Base64::constantUrlEncodeNoPadding($data))->toBe(sodium_bin2base64($data, SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING))
        ->and(Base64::constantUrlDecode(Base64::constantUrlEncode($data)))->toBe($data)
        ->and(Base64::constantUrlDecodeNoPadding(Base64::constantUrlEncodeNoPadding($data)))->toBe($data);
});

it('calculates lengths', function (): void {
    expect(Base64::decodedLength(4))->toBe(3)
        ->and(Base64::decodedLength(3, false))->toBe(2)
        ->and(Base64::encodedLength(3))->toBe(3)
        ->and(Base64::encodedLength(3, false))->toBe(4);
});
