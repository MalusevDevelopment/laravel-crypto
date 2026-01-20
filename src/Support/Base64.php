<?php

declare(strict_types=1);

namespace CodeLieutenant\LaravelCrypto\Support;

final class Base64
{
    public static function encode(string $binary): string
    {
        return base64_encode($binary);
    }

    public static function encodeNoPadding(string $binary): string
    {
        return rtrim(base64_encode($binary), '=');
    }

    public static function decode(string $base64): string
    {
        return base64_decode($base64, true);
    }

    public static function urlEncode(string $binary): string
    {
        return strtr(base64_encode($binary), '+/', '-_');
    }

    public static function urlEncodeNoPadding(string $binary): string
    {
        return rtrim(strtr(base64_encode($binary), '+/', '-_'), '=');
    }

    public static function urlDecode(string $base64): string
    {
        return base64_decode(strtr($base64, '-_', '+/'), true);
    }

    public static function constantEncode(string $binary): string
    {
        return sodium_bin2base64($binary, SODIUM_BASE64_VARIANT_ORIGINAL);
    }

    public static function constantEncodeNoPadding(string $binary): string
    {
        return sodium_bin2base64($binary, SODIUM_BASE64_VARIANT_ORIGINAL_NO_PADDING);
    }

    public static function constantDecode(string $binary): string
    {
        return sodium_base642bin($binary, SODIUM_BASE64_VARIANT_ORIGINAL);
    }

    public static function constantUrlEncode(string $binary): string
    {
        return sodium_bin2base64($binary, SODIUM_BASE64_VARIANT_URLSAFE);
    }

    public static function constantUrlEncodeNoPadding(string $binary): string
    {
        return sodium_bin2base64($binary, SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING);
    }

    public static function constantUrlDecode(string $binary): string
    {
        return sodium_base642bin($binary, SODIUM_BASE64_VARIANT_URLSAFE);
    }

    public static function constantUrlDecodeNoPadding(string $binary): string
    {
        return sodium_base642bin($binary, SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING);
    }

    public static function decodedLength(int $bufferLength, bool $hasPadding = true): int
    {
        return match ($hasPadding) {
            true => intdiv($bufferLength, 4) * 3,
            false => intdiv($bufferLength * 6, 8),
        };
    }

    public static function encodedLength(int $bufferLength, bool $hasPadding = true): int
    {
        return match ($hasPadding) {
            true => intdiv($bufferLength + 2, 3) * 3,
            false => intdiv(($bufferLength * 8 + 5), 6),
        };
    }
}
