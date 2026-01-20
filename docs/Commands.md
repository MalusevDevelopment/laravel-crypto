# Console Commands

Laravel Crypto provides a command to generate and manage cryptographic keys used by the package.

## Generating Keys

You can generate all necessary keys for the package using the `crypto:keys` command. This command is designed to be a drop-in replacement or supplement to Laravel's default `key:generate`.

```bash
php artisan crypto:keys
```

By default, this command will generate:
- **Application Key (`APP_KEY`)**: Used for general encryption.
- **EdDSA Key Pair**: Used for asymmetric signing.
- **Blake2b Hashing Key**: Used for keyed hashing.
- **HMAC Key**: Used for symmetric signing.

### Options

| Option | Description |
| --- | --- |
| `--force` | Force the operation to run when in production environment. |
| `--show` | Display the keys in the console instead of modifying files. |
| `--no-eddsa` | Do **not** generate the EdDSA (Ed25519) key pair. |
| `--no-app` | Do **not** generate the application key. |
| `--no-blake2b` | Do **not** generate the Blake2b hashing key. |
| `--no-hmac` | Do **not** generate the HMAC key. |

### Environment Variables

The command updates (or shows) the following environment variables in your `.env` file:

- `APP_KEY`
- `CRYPTO_BLAKE2B_HASHING_KEY`
- `CRYPTO_HMAC_KEY`

For **EdDSA**, the keys are saved to a file specified in your `config/crypto.php` (defaulting to `storage/keys/eddsa.key`). The environment variable `CRYPTO_EDDSA_PUBLIC_CRYPTO_KEY` points to this file.
