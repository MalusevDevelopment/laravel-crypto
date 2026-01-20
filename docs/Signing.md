# Signing

Laravel Crypto supports both Symmetric (HMAC) and Asymmetric (EdDSA) signing.

## Symmetric Signing (HMAC)

HMAC (Hash-based Message Authentication Code) uses a shared secret key to sign and verify data.

### Supported HMAC Algorithms

- `Blake2b` (Default)
- `Sha256`
- `Sha512`

### Configuration

Set your default signing driver and key in `config/crypto.php`:

```php
'signing' => [
    'driver' => CodeLieutenant\LaravelCrypto\Signing\Hmac\Blake2b::class,
    'keys' => [
        'hmac' => env('CRYPTO_HMAC_KEY'),
    ],
],
```

### Usage

Use the `Sign` facade for easy access to signing methods.

```php
use CodeLieutenant\LaravelCrypto\Facades\Sign;

$signature = Sign::sign('my data');

if (Sign::verify('my data', $signature)) {
    // Signature is valid
}
```

You can also use specific algorithms:

```php
$sig = Sign::hmac256Sign('data');
Sign::hmac256Verify('data', $sig);
```

## Asymmetric Signing (EdDSA)

EdDSA (specifically Ed25519) uses a public/private key pair. You sign data with your private key, and others can verify it using your public key.

### Configuration

Ensure the path to your EdDSA key is set in `config/crypto.php`:

```php
'signing' => [
    'keys' => [
        'eddsa' => env('CRYPTO_EDDSA_PUBLIC_CRYPTO_KEY', storage_path('keys/eddsa.key')),
    ],
],
```

Generate the key pair using:

```bash
php artisan crypto:keys
```

### Usage

```php
use CodeLieutenant\LaravelCrypto\Facades\Sign;

$signature = Sign::eddsaSign('my data');

if (Sign::eddsaVerify('my data', $signature)) {
    // Signature is valid
}
```
