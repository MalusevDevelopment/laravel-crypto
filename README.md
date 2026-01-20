# Laravel Crypto

[![Run Tests](https://github.com/dmalusev/laravel-crypto/actions/workflows/test.yml/badge.svg?branch=master)](https://github.com/dmalusev/laravel-crypto/actions/workflows/test.yml)
[![GitHub issues](https://img.shields.io/github/issues/malusev998/LaravelCrypto?label=Github%20Issues)](https://github.com/malusev998/LaravelCrypto/issues)
[![GitHub stars](https://img.shields.io/github/stars/malusev998/LaravelCrypto?label=Github%20Stars)](https://github.com/malusev998/LaravelCrypto/stargazers)
[![GitHub license](https://img.shields.io/github/license/malusev998/LaravelCrypto?label=Licence)](https://github.com/malusev998/LaravelCrypto)

Laravel Crypto provides a simple and easy-to-use API for encrypting, decrypting, hashing, and signing data using modern cryptographic algorithms powered by `libsodium`.

## Why Laravel Crypto?

- **Modern Algorithms**: Support for XChaCha20-Poly1305, AES-256-GCM, Blake2b, and EdDSA.
- **Performance**: High-performance cryptographic operations utilizing hardware acceleration where available.
- **Drop-in Replacement**: Seamlessly replaces Laravel's default `EncryptionServiceProvider`.
- **Comprehensive**: Includes support for hashing, signing (symmetric and asymmetric), and various data encoders (JSON, MessagePack, Igbinary).

## Requirements

- **PHP**: 8.4 or higher
- **Extensions**: `ext-sodium`
- **Laravel**: 10.x, 11.x, or 12.x

## Getting Started

### 1. Installation

```bash
composer require codelieutenant/laravel-crypto
```

### 2. Service Provider Registration

In order to activate the package, you need to replace Laravel's default `EncryptionServiceProvider` with `CodeLieutenant\LaravelCrypto\ServiceProvider`.

#### Laravel 11.x & 12.x

In `bootstrap/providers.php`, replace the default provider:

```php
return [
    App\Providers\AppServiceProvider::class,
    // Illuminate\Encryption\EncryptionServiceProvider::class, // Remove or comment out
    CodeLieutenant\LaravelCrypto\ServiceProvider::class,       // Add this
];
```

#### Laravel 10.x

In `config/app.php`, replace `Illuminate\Encryption\EncryptionServiceProvider::class` in the `providers` array:

```php
'providers' => [
    // ...
    // Illuminate\Encryption\EncryptionServiceProvider::class,
    CodeLieutenant\LaravelCrypto\ServiceProvider::class,
    // ...
],
```

### 3. Configuration

Publish the configuration file:

```bash
php artisan vendor:publish --provider="CodeLieutenant\LaravelCrypto\ServiceProvider"
```

Update your `cipher` in `config/app.php`:

```php
'cipher' => 'Sodium_AES256GCM', // Options: Sodium_AES256GCM, Sodium_XChaCha20Poly1305, Sodium_AEGIS256GCM, Sodium_AEGIS128LGCM
```

### 4. Generating Keys

Generate the necessary cryptographic keys:

```bash
php artisan crypto:keys
```

This will update your `.env` file with the required keys and generate an EdDSA key pair in `storage/keys/`.

## Usage Overview

### Encryption

Uses the standard Laravel `Crypt` facade but with Sodium algorithms.

```php
use Illuminate\Support\Facades\Crypt;

$encrypted = Crypt::encryptString('Hello Sodium');
$decrypted = Crypt::decryptString($encrypted);
```

### Hashing

High-performance hashing using Blake2b.

```php
use CodeLieutenant\LaravelCrypto\Facades\Hashing;

$hash = Hashing::hash('data');
```

### Signing

Symmetric (HMAC) and Asymmetric (EdDSA) signing.

```php
use CodeLieutenant\LaravelCrypto\Facades\Sign;

// HMAC
$sig = Sign::sign('message');

// EdDSA
$sig = Sign::eddsaSign('message');
```

## Performance

Benchmarks conducted on various data sizes (PHP 8.5.1, Sodium extension enabled) on a Macbook M4 Pro 48GB RAM.

### 1 KiB Payload

| Algorithm | Encryption | Decryption |
|-----------|------------|------------|
| Laravel AES-256-CBC | 8.09 μs | 9.98 μs |
| Laravel AES-256-GCM | 3.37 μs | 5.33 μs |
| **Sodium AES-256-GCM** | 2.39 μs | 2.58 μs |
| **Sodium AEGIS-128L** | **2.03 μs** | **2.14 μs** |
| **Sodium AEGIS-256** | 2.06 μs | 2.27 μs |
| Sodium XChaCha20-Poly1305 | 3.41 μs | 3.58 μs |

### 32 KiB Payload

| Algorithm | Encryption | Decryption |
|-----------|------------|------------|
| Laravel AES-256-CBC | 151.01 μs | 181.81 μs |
| Laravel AES-256-GCM | 35.81 μs | 81.98 μs |
| **Sodium AES-256-GCM** | 26.93 μs | 29.22 μs |
| **Sodium AEGIS-128L** | **18.23 μs** | **20.68 μs** |
| **Sodium AEGIS-256** | 18.86 μs | 21.82 μs |
| Sodium XChaCha20-Poly1305 | 58.40 μs | 60.90 μs |

### 1 MiB Payload

| Algorithm | Encryption | Decryption |
|-----------|------------|------------|
| Laravel AES-256-CBC | 5.02 ms | 7.57 ms |
| Laravel AES-256-GCM | 1.31 ms | 3.94 ms |
| **Sodium AES-256-GCM** | 1.11 ms | 1.88 ms |
| **Sodium AEGIS-128L** | 0.90 ms | **1.60 ms** |
| **Sodium AEGIS-256** | **0.82 ms** | 1.65 ms |
| Sodium XChaCha20-Poly1305 | 2.21 ms | 2.90 ms |

Sodium-based algorithms provide more consistent performance and are significantly faster for decryption of large payloads compared to Laravel's default implementations. AEGIS algorithms offer top-tier performance on modern hardware.

## Documentation

For detailed information, please refer to the following documentation:

- [Console Commands](docs/Commands.md)
- [Encryption](docs/Encryption.md)
- [Hashing](docs/Hashing.md)
- [Signing](docs/Signing.md)
- [Utilities (Encoders, Base64, Random)](docs/Utilities.md)

## License

The MIT License (MIT). Please see [License File](LICENCE) for more information.
