# Hashing

Laravel Crypto provides high-performance hashing algorithms, specifically optimized for speed and security.

## Supported Algorithms

- `Blake2b`: A high-performance cryptographic hash function that is faster than MD5, SHA-1, SHA-2, and SHA-3, yet is at least as secure as the latest standard SHA-3.
- `Sha256`: Standard SHA-256 implementation.
- `Sha512`: Standard SHA-512 implementation.

## Configuration

You can configure the default hashing driver in `config/crypto.php`:

```php
'hashing' => [
    'driver' => CodeLieutenant\LaravelCrypto\Hashing\Blake2b::class,
    'config' => [
        CodeLieutenant\LaravelCrypto\Hashing\Blake2b::class => [
            'key' => env('CRYPTO_BLAKE2B_HASHING_KEY'),
            'outputLength' => 32,
        ],
    ],
],
```

## Usage

You can use the `Hashing` facade provided by this package.

### Basic Hashing

```php
use CodeLieutenant\LaravelCrypto\Facades\Hashing;

$hash = Hashing::hash('some data');
```

### Keyed Hashing (Blake2b)

Blake2b supports keyed hashing, which makes it act like an HMAC. This is useful for creating unique hashes for your application.

```php
// In config/crypto.php, set the 'key'
$hash = Hashing::hash('some data'); // Uses the configured key
```

### Verification

Note that these hashers are NOT for password hashing (use Laravel's `Hash` facade with Argon2 for that). These are for data integrity and general-purpose cryptographic hashing.

```php
if (Hashing::verify($hash, 'data')) {
    // Integrity verified
}
```

### Constant-Time Comparison

To prevent timing attacks when comparing hashes, you can use the `equals` method:

```php
if (Hashing::equals($hash1, $hash2)) {
    // Hashes are equal
}
```
