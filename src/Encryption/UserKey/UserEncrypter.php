<?php

declare(strict_types=1);

namespace CodeLieutenant\LaravelCrypto\Encryption\UserKey;

use CodeLieutenant\LaravelCrypto\Contracts\UserEncryptionContext as UserEncryptionContextContract;
use CodeLieutenant\LaravelCrypto\Exceptions\MissingEncryptionContextException;
use Illuminate\Contracts\Encryption\DecryptException;
use Illuminate\Contracts\Encryption\EncryptException;
use Illuminate\Encryption\Encrypter as LaravelEncrypter;

/**
 * Primary developer-facing API for per-user encryption.
 *
 * Inject this class (or resolve via the UserCrypt facade) in controllers,
 * jobs, and services that need to encrypt/decrypt data on behalf of the
 * current user.
 *
 * The key is read from the request-scoped UserEncryptionContext — it is
 * never stored on the server; it lives only for the duration of the request.
 *
 * ## Usage
 *
 *   // In a controller (injected via the container):
 *   public function store(Request $request, UserEncrypter $crypt): JsonResponse
 *   {
 *       $ciphertext = $crypt->encryptString($request->input('ssn'));
 *       ...
 *   }
 *
 *   // Via the facade:
 *   $ciphertext = UserCrypt::encryptString($ssn);
 *   $ssn        = UserCrypt::decryptString($ciphertext);
 */
final class UserEncrypter
{
    public function __construct(
        private readonly UserEncryptionContextContract $context,
    ) {}

    /** @throws MissingEncryptionContextException|EncryptException */
    public function encrypt(mixed $value, bool $serialize = true): string
    {
        return $this->makeEncrypter()->encrypt($value, $serialize);
    }

    /** @throws MissingEncryptionContextException|DecryptException */
    public function decrypt(string $payload, bool $unserialize = true): mixed
    {
        return $this->makeEncrypter()->decrypt($payload, $unserialize);
    }

    /** @throws MissingEncryptionContextException|EncryptException */
    public function encryptString(string $value): string
    {
        return $this->makeEncrypter()->encryptString($value);
    }

    /** @throws MissingEncryptionContextException|DecryptException */
    public function decryptString(string $payload): string
    {
        return $this->makeEncrypter()->decryptString($payload);
    }

    /** True if a key is loaded for the current request. */
    public function hasContext(): bool
    {
        return $this->context->has();
    }

    private function makeEncrypter(): LaravelEncrypter
    {
        $key = $this->context->get(); // throws MissingEncryptionContextException if not set

        return new LaravelEncrypter($key, 'AES-256-CBC');
    }
}

