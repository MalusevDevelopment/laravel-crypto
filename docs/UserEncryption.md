# User Encryption

User Encryption provides an additional layer of security by encrypting data with a key unique to each user. Unlike application-level encryption, where one `APP_KEY` encrypts all data, User Encryption ensures that even if your database and `APP_KEY` are compromised, a user's sensitive data remains unreadable without their unique key.

## Key Concepts

- **Per-User Key Derivation**: Each user has their own unique encryption key derived from their password or a secret they provide.
- **Wrapped Keys**: The user's encryption key is stored in the database in a "wrapped" (encrypted) state, typically using the `APP_KEY`.
- **Request-Scoped Context**: The decrypted user key exists only in memory for the duration of a single HTTP request or job, after which it is securely wiped from memory.
- **Blind Indexes**: Support for searching encrypted data without decrypting it, using deterministic hashes (blind indexes) that can be scoped to the user or globally.

## Setup

### 1. Database Migration

Your `users` table needs a column to store the encrypted key blob. You can use the provided helper in your migration:

```php
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

Schema::table('users', function (Blueprint $table) {
    // Adds 'encryption_key_id' as a binary column
    $table->binary('encryption_key_id')->nullable();
});
```

### 2. Prepare the User Model

Add the `HasUserEncryption` trait to your `User` model. This trait provides methods for initializing, wrapping, and unwrapping the user's key.

```php
namespace App\Models;

use CodeLieutenant\LaravelCrypto\Traits\HasUserEncryption;
use Illuminate\Foundation\Auth\User as Authenticatable;

class User extends Authenticatable
{
    use HasUserEncryption;

    // ...
}
```

### 3. Initialize User Encryption

When a user signs up or provides their password for the first time, you must initialize their encryption key:

```php
$user = User::create([...]);
$user->initUserEncryption($password);
$user->save();
```

This derives a master key from the password, wraps it, and stores the blob in `encryption_key_id`.

## Usage in Eloquent Models

You can use specialized casts to encrypt attributes with the user's key. These attributes can only be decrypted when the user's key is present in the request context.

### Encrypted Attributes

```php
use CodeLieutenant\LaravelCrypto\Casts\UserEncryptedWithIndex;

class UserSecret extends Model
{
    protected function casts(): array
    {
        return [
            // Basic user encryption with a blind index for searching
            'ssn' => UserEncryptedWithIndex::class . ':ssn_index',
        ];
    }
}
```

### Searching with Blind Indexes

Blind indexes allow you to search for encrypted values. They are deterministic hashes of the plaintext. The package uses `BLAKE2b` for hashing and ensures per-user and per-column isolation using libsodium's KDF.

#### 1. Add the index column to your migration

```php
Schema::create('user_secrets', function (Blueprint $table) {
    $table->id();
    $table->foreignId('user_id')->constrained();
    $table->binary('ssn');
    $table->blindIndex('ssn'); // Adds 'ssn_index' as binary(32)
    $table->timestamps();
});
```

#### 2. Querying

You can use the `UserCrypt` facade to compute the blind index for a search query.

```php
use CodeLieutenant\LaravelCrypto\Facades\UserCrypt;

// Search for a specific user's secret
$secret = UserSecret::where('user_id', $user->id)
    ->where('ssn_index', UserCrypt::blindIndex('123-45-6789', 'ssn'))
    ->first();
```

### Global Blind Indexes

If you need to search across multiple users (e.g., checking if an email is already registered anywhere in the system), use `global` mode. This uses a site-wide key instead of the user's personal key for the index.

```php
'email' => UserEncryptedWithIndex::class . ':email_index,true,global',
```

Querying a global index:

```php
$exists = User::where('email_index', UserCrypt::globalBlindIndex($email, 'email'))->exists();
```

## Middleware and Authentication

To make user encryption "seamless," you should use the provided middleware. This middleware ensures that whenever a user logs in, their encryption key is unwrapped and placed into the request-scoped context.

### Automatic Key Unwrapping

For web applications, the package provides the `BootPerUserEncryption` middleware. This middleware ensures that whenever a user is authenticated, their encryption key is available in the request context.

It supports multiple transport mechanisms:
1.  **X-Encryption-Token Header**: Useful for SPAs and API clients.
2.  **`enc_token` Cookie**: An HTTP-only cookie for traditional web applications.
3.  **Auto-Derivation**: If no token is provided, the middleware can automatically derive a key based on the `APP_KEY` and the User ID (if configured).

#### Registering Middleware

In `bootstrap/app.php` (Laravel 11+):

```php
->withMiddleware(function (Middleware $middleware) {
    $middleware->append(CodeLieutenant\LaravelCrypto\Http\Middleware\BootPerUserEncryption::class);
})
```

*Note: Ensure it runs after the authentication middleware.*

### Manual Key Management

In your `Auth` controller or where you handle logins, you can manually issue tokens:

```php
if (Auth::attempt($credentials)) {
    $user = Auth::user();
    // Decrypt the user's master key and store it in memory for this request
    $user->issueEncryptionToken($credentials['password']);
    
    return redirect()->intended();
}
```

### Request Lifecycle

For subsequent requests, you need to ensure the key is available. Since the decrypted key is never stored in the session or cookies (for security), you have two options:

1.  **Password-based**: The user must provide their password (or it must be available) to unwrap the key.
2.  **Token-based**: Store a temporary per-session "access token" (which is the decrypted user key or a derivative) in the session.

*Note: The implementation details for automatic session-based persistence depend on your application's security requirements.*

## Advanced Features

### Composite Blind Indexes

You can make blind indexes unique within a certain context (e.g., unique per `user_id` and `label`):

```php
// In the model cast
'secret_value' => UserEncryptedWithIndex::class . ':secret_value_index,true,user,label',
```

The `context` parameter (last argument) tells the indexer to include the value of the `label` column when hashing the `secret_value`.

### JSON Encryption

Encrypt entire JSON arrays/objects with the user's key:

```php
'metadata' => UserEncryptedJsonWithIndex::class . ':metadata_index',
```

## Security Best Practices

1.  **Memory Safety**: Always use the `UserEncryptionContext` to hold keys. It uses `sodium_memzero` to wipe keys when they are no longer needed.
2.  **Password Changes**: If a user changes their password, you must re-wrap their encryption key using the `rewrapUserEncryption($oldPassword, $newPassword)` method.
3.  **High Entropy**: Use libsodium's KDF for key derivation (handled automatically by `initUserEncryption`).
4.  **Blind Index Leaks**: Remember that blind indexes leak equality. Two identical plaintexts will produce the same index. Use them only for fields with high cardinality.
