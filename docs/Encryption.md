# Encryption

Laravel Crypto provides a faster and more secure alternative to Laravel's default encryption by utilizing `libsodium`.

## Supported Ciphers

The package supports the following Sodium ciphers:

- `Sodium_AES256GCM`: AES-256-GCM using hardware acceleration (if available).
- `Sodium_XChaCha20Poly1305`: XChaCha20-Poly1305, a modern and high-performance cipher.
- `Sodium_AEGIS256GCM`: AEGIS-256-GCM, a high-performance, modern Authenticated Encryption with Associated Data (AEAD) algorithm.
- `Sodium_AEGIS128LGCM`: AEGIS-128L-GCM, a high-performance, modern AEAD algorithm.
- `Sodium_SecretBox`: XSalsa20-Poly1305 (libsodium secretbox).

## Configuration

To use these ciphers, update your `config/app.php` file:

```php
'cipher' => 'Sodium_AES256GCM', // or 'Sodium_XChaCha20Poly1305', 'Sodium_AEGIS256GCM', 'Sodium_AEGIS128LGCM', 'Sodium_SecretBox'
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

## File Encryption

Laravel Crypto introduces high-level file encryption through the `Crypt` facade. It supports chunked encryption to handle large files efficiently without consuming much memory.

### Basic Usage

```php
use Illuminate\Support\Facades\Crypt;

// Encrypt a file
Crypt::encryptFile('path/to/input.txt', 'path/to/output.enc');

// Decrypt a file
Crypt::decryptFile('path/to/output.enc', 'path/to/decrypted.txt');
```

### Drivers

You can configure the file encryption driver in `config/crypto.php`:

```php
'file_encryption' => [
    'driver' => CodeLieutenant\LaravelCrypto\Encryption\File\SecretStreamFileEncrypter::class,
    // ...
],
```

Supported drivers:
- `SecretStreamFileEncrypter` (Default): Uses libsodium's `secretstream` (XChaCha20-Poly1305) for secure, chunked streaming.
- `NativeFileEncrypter`: Uses the same algorithm as your main application encryption (configured in `config/app.php`).
- `XSalsaHmacFileEncrypter`: Uses XSalsa20 for encryption and HMAC for authentication in a chunked manner.

### Separate Keys

For enhanced security, you can use a separate key for file encryption by setting the `CRYPTO_FILE_ENCRYPTION_KEY` environment variable. If not set, it will fallback to the standard `APP_KEY`.

```env
CRYPTO_FILE_ENCRYPTION_KEY=base64:your-file-key...
```

## Key Rotation (Previous Keys)

Laravel Crypto supports key rotation for both general encryption and file encryption. You can specify previous keys to ensure that data encrypted with old keys can still be decrypted.

For application encryption, use `APP_PREVIOUS_KEYS`:
```env
APP_PREVIOUS_KEYS=key1,key2,key3
```

For file encryption, use `CRYPTO_FILE_ENCRYPTION_PREVIOUS_KEYS`:
```env
CRYPTO_FILE_ENCRYPTION_PREVIOUS_KEYS=key1,key2,key3
```

## Eloquent Casting for Encrypted Files

Storing entire files directly inside a database is generally considered a bad practice. `Laravel Crypto` provides an Eloquent caster that allows you to store the *path* of an encrypted file in your database, while the model automatically handles decryption and re-encryption for you.

### Usage in Models

To use the caster, simply add it to the `$casts` property of your Eloquent model:

```php
use CodeLieutenant\LaravelCrypto\Casts\EncryptedFileCast;
use CodeLieutenant\LaravelCrypto\Support\EncryptedFile;
use Illuminate\Database\Eloquent\Model;

class UserDocument extends Model
{
    protected $casts = [
        'file_path' => EncryptedFileCast::class,
    ];
}
```

When you retrieve the model, the `file_path` attribute will return an instance of `CodeLieutenant\LaravelCrypto\Support\EncryptedFile`.

### The `EncryptedFile` Object

The `EncryptedFile` object manages the lifecycle of the encrypted file and provides on-the-fly decryption to a temporary location.

#### Reading Content

You can read the decrypted content as a string or as a stream:

```php
$userDocument = UserDocument::find(1);

// Get the full string content
$content = $userDocument->file_path->contents();

// Or get a readable stream (resource)
$stream = $userDocument->file_path->stream();
$content = stream_get_contents($stream);
fclose($stream);
```

#### Modifying Content

When you modify the decrypted file, the caster will automatically detect that it's "dirty" and re-encrypt the file before saving the model:

```php
$userDocument = UserDocument::find(1);

// Using the helper method to update content
$userDocument->file_path->putContents('New file content');

// OR access the temporary decrypted path directly and write to it
$decryptedPath = $userDocument->file_path->getDecryptedPath();
file_put_contents($decryptedPath, 'Updated through path');

// Save the model - it will automatically re-encrypt the file
$userDocument->save();
```

#### Moving or Setting a New File

You can also change the destination of the encrypted file or provide a new decrypted file to be encrypted:

```php
$userDocument = new UserDocument;

// Point to where we want the encrypted file to be stored
$encryptedFile = new EncryptedFile('storage/app/encrypted/my_file.enc');

// Provide the initial content (this will be encrypted on save)
$encryptedFile->putContents('Initial sensitive data');

$userDocument->file_path = $encryptedFile;
$userDocument->save();

// Later, you can change the storage path
$userDocument->file_path->setEncryptedPath('storage/app/archived/old_file.enc');
$userDocument->save(); // File is moved and re-encrypted to the new path
```

#### Lifecycle and Cleanup

The `EncryptedFile` object automatically cleans up its temporary decrypted file when it is destroyed (via the destructor). This ensures that unencrypted data does not linger on your server's temporary storage.

## Security Note

Laravel Crypto uses `AEAD` (Authenticated Encryption with Associated Data). In all supported ciphers, the nonce is automatically generated and prepended to the ciphertext. File encryption uses chunked processing to ensure data integrity even for very large files.
