# Encryption

Laravel Crypto provides a faster and more secure alternative to Laravel's default encryption by utilizing `libsodium`.

## Supported Ciphers

The package supports the following Sodium ciphers:

- `Sodium_AES256GCM`: AES-256-GCM using hardware acceleration (if available).
- `Sodium_XChaCha20Poly1305`: XChaCha20-Poly1305, a modern and high-performance cipher.

## Configuration

To use these ciphers, update your `config/app.php` file:

```php
'cipher' => 'Sodium_AES256GCM', // or 'Sodium_XChaCha20Poly1305'
```

Ensure you have generated a compatible key using:

```bash
php artisan crypto:keys
```

## Usage

Since Laravel Crypto integrates directly into Laravel's encryption system, you can use the `Crypt` facade or the `Encrypter` contract as usual.

### Basic Usage

```php
use Illuminate\Support\Facades\Crypt;

$encrypted = Crypt::encryptString('Hello World');
$decrypted = Crypt::decryptString($encrypted);
```

### Encrypting Objects/Arrays

By default, Laravel Crypto uses the `PhpEncoder` (which uses `serialize`/`unserialize`). You can change this to `JsonEncoder` or other supported encoders in `config/crypto.php`.

```php
$data = ['key' => 'value'];
$encrypted = Crypt::encrypt($data);
$decrypted = Crypt::decrypt($encrypted);
```

## Security Note

Laravel Crypto uses `AEAD` (Authenticated Encryption with Associated Data). In the case of `Sodium_AES256GCM` and `Sodium_XChaCha20Poly1305`, the nonce is automatically generated and prepended to the ciphertext.
