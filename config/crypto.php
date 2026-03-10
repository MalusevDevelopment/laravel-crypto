<?php

declare(strict_types=1);

use CodeLieutenant\LaravelCrypto\Encoder\JsonEncoder;
use CodeLieutenant\LaravelCrypto\Encoder\PhpEncoder;
use CodeLieutenant\LaravelCrypto\Encryption\File\SecretStreamFileEncrypter;
use CodeLieutenant\LaravelCrypto\Hashing\Blake2b as Blake2bHash;
use CodeLieutenant\LaravelCrypto\Hashing\Sha256 as Sha256Hash;
use CodeLieutenant\LaravelCrypto\Hashing\Sha512 as Sha512Hash;
use CodeLieutenant\LaravelCrypto\Signing\Hmac\Blake2b as Blake2bHMAC;
use CodeLieutenant\LaravelCrypto\Signing\Hmac\Sha256 as Sha256HMAC;
use CodeLieutenant\LaravelCrypto\Signing\Hmac\Sha512 as Sha512HMAC;

return [
    /*
    |--------------------------------------------------------------------------
    | Crypto Encoder
    |--------------------------------------------------------------------------
    |
    | This option controls the default encoder that will be used to encode
    | and decode data thought the library. Can be any implementing class
    | of `Encoder` interface. Use `config` to pass any configuration
    | to the underlying encoder. There is no need to register encoder
    | in the service provider, it will be resolved automatically
    | if only everything that class requires is in `config`.
    |
    */

    'encoder' => [
        'driver' => PhpEncoder::class,
        'config' => [
            PhpEncoder::class => [
                'allowed_classes' => true,
            ],
            JsonEncoder::class => [
                'decode_as_array' => true,
            ],
        ],
    ],

    /*
    |--------------------------------------------------------------------------
    | Hashing
    |--------------------------------------------------------------------------
    |
    | This option controls the default hashing algorithm that will be used
    | to hash data. Can be any implementing class of `Hashing` interface.
    | Use `config` to pass any configuration to the underlying hashing.
    |
    | In `blake2b` case, you can pass `key` and `outputLength` to the config.
    | `key` is used to have unique hash for your application even if the data
    | is the same. There is no difference between `HMAC` version and `Hash`
    | version of the algorithm when `key` is used.
    |
    */
    'hashing' => [
        'driver' => Blake2bHash::class,
        'config' => [
            Blake2bHash::class => [
                'key' => env('CRYPTO_BLAKE2B_HASHING_KEY'),
                'outputLength' => 32,
            ],
            Sha256Hash::class => [],
            Sha512Hash::class => [],
        ],
    ],

    /*
    |--------------------------------------------------------------------------
    | File Encryption
    |--------------------------------------------------------------------------
    |
    | This option controls the default algorithm that will be used to encrypt
    | files. By default, it uses `SecretStream` from libsodium (XChaChaPoly1305).
    | You can also use `NativeFileEncrypter::class` to use the same algorithm
    | as the APP encryption or `XSalsaHmacFileEncrypter::class` for
    | XSalsa20 + HMAC chunked encryption.
    |
    | You can also specify a separate key for file encryption. If not set,
    | it will fallback to `app.key` and `app.previous_keys`.
    |
    */
    'file_encryption' => [
        'driver' => env('CRYPTO_FILE_ENCRYPTION_ALGORITHM', SecretStreamFileEncrypter::class),
        'key' => env('CRYPTO_FILE_ENCRYPTION_KEY', env('APP_KEY')),
        'previous_keys' => env('CRYPTO_FILE_ENCRYPTION_PREVIOUS_KEYS', env('APP_PREVIOUS_KEYS', '')),
    ],

    /*
    |--------------------------------------------------------------------------
    | Per-User Encryption
    |--------------------------------------------------------------------------
    |
    | Controls how the per-user encryption key token is transported between
    | the server and the client.
    |
    | token_header   — HTTP request/response header name used by SPA / API clients.
    |
    | cookie_name    — HTTP-only cookie name used by web (browser) clients.
    |                  Set to null to disable cookie transport entirely.
    |
    | cookie_encrypt — When true, the cookie value is encrypted with Laravel's
    |                  default encrypter (APP_KEY) before being written, and
    |                  decrypted transparently on read.  This adds a second layer
    |                  of protection for the token at rest in the browser cookie jar.
    |
    | cookie_http_only — Prevents JavaScript from reading the cookie.
    |                    Should always be true (this is the whole point).
    |
    | cookie_secure  — Send the cookie only over HTTPS. Defaults to the value
    |                  of the 'session.secure' config key.
    |
    | cookie_same_site — SameSite cookie attribute. 'lax' is a good default for
    |                    web apps; use 'strict' for maximum CSRF protection.
    |
    | cookie_ttl     — Cookie lifetime in minutes. 0 = session cookie (deleted
    |                  when the browser closes). Default: 120 minutes.
    |
    | opslimit / memlimit — Argon2id parameters for password-wrapped blobs.
    |
    */
    'per_user' => [
        'token_header' => env('CRYPTO_PER_USER_TOKEN_HEADER', 'X-Encryption-Token'),
        'cookie_name' => env('CRYPTO_PER_USER_COOKIE_NAME', 'enc_token'),
        'cookie_encrypt' => (bool) env('CRYPTO_PER_USER_COOKIE_ENCRYPT', true),
        'cookie_http_only' => true,
        'cookie_secure' => env('CRYPTO_PER_USER_COOKIE_SECURE', env('SESSION_SECURE_COOKIE', false)),
        'cookie_same_site' => env('CRYPTO_PER_USER_COOKIE_SAME_SITE', 'lax'),
        'cookie_ttl' => (int) env('CRYPTO_PER_USER_COOKIE_TTL', 120),
        'opslimit' => SODIUM_CRYPTO_PWHASH_OPSLIMIT_INTERACTIVE,
        'memlimit' => SODIUM_CRYPTO_PWHASH_MEMLIMIT_INTERACTIVE,
    ],

    /*
    |--------------------------------------------------------------------------
    |
    | Used to crypto sign the data. Can be any implementing class of `Signer`
    | interface.
    | For the signer there is implementation with asymmetric and symmetric
    | MAC algorithm. For the asymmetric algorithm, you can use `EdDSA`
    | and for the symmetric MAC algorithm, you can use `Blake2b`, `Sha256` and `Sha512`.
    |
    | `Sha256` uses `sha512/256` implemented in `libsodium`.
    |
    */
    'signing' => [
        'driver' => Blake2bHMAC::class,
        'keys' => [
            'eddsa' => env('CRYPTO_EDDSA_PUBLIC_CRYPTO_KEY', storage_path('keys/eddsa.key')),
            'hmac' => env('CRYPTO_HMAC_KEY'),
        ],
        'config' => [
            Blake2bHMAC::class => [
                'outputLength' => 32,
            ],
            Sha256HMAC::class => [],
            Sha512HMAC::class => [],
        ],
    ],
];
