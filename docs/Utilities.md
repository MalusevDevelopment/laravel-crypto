# Utilities

Laravel Crypto provides several utility classes for common cryptographic tasks, such as encoding and random number generation.

## Encoders

Encoders are used by the encryption system to prepare data before it is encrypted and to restore it after decryption.

| Encoder | Description | Requirement |
| --- | --- | --- |
| `PhpEncoder` | Uses PHP's `serialize()` and `unserialize()`. | None |
| `JsonEncoder` | Uses `json_encode()` and `json_decode()`. | `ext-json` |
| `MessagePackEncoder` | Uses MessagePack format. | `ext-msgpack` |
| `IgbinaryEncoder` | Uses Igbinary format. | `ext-igbinary` |

### Configuration

You can set the default encoder in `config/crypto.php`:

```php
'encoder' => [
    'driver' => CodeLieutenant\LaravelCrypto\Encoder\PhpEncoder::class,
    'config' => [
        CodeLieutenant\LaravelCrypto\Encoder\PhpEncoder::class => [
            'allowed_classes' => true,
        ],
        CodeLieutenant\LaravelCrypto\Encoder\JsonEncoder::class => [
            'decode_as_array' => true,
        ]
    ],
],
```

## Base64

The `CodeLieutenant\LaravelCrypto\Support\Base64` class provides constant-time Base64 encoding and decoding using `libsodium`.

### Constant-Time Methods (Recommended)

Constant-time methods are safer as they help prevent timing attacks.

```php
use CodeLieutenant\LaravelCrypto\Support\Base64;

$encoded = Base64::constantUrlEncodeNoPadding($binaryData);
$decoded = Base64::constantUrlDecodeNoPadding($encoded);
```

Available constant-time variants:
- `constantEncode` / `constantDecode`
- `constantEncodeNoPadding`
- `constantUrlEncode` / `constantUrlDecode`
- `constantUrlEncodeNoPadding` / `constantUrlDecodeNoPadding`

## Random

The `CodeLieutenant\LaravelCrypto\Support\Random` class provides cryptographically secure random values.

```php
use CodeLieutenant\LaravelCrypto\Support\Random;

// Generate random bytes
$bytes = Random::bytes(32);

// Generate a random URL-safe string
$string = Random::string(16);

// Generate a random integer
$int = Random::int(1, 100);
```
