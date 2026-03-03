<?php

declare(strict_types=1);

namespace CodeLieutenant\LaravelCrypto\Exceptions;

use RuntimeException;

/**
 * Thrown when a per-user encrypted cast or encrypter is accessed but
 * the UserEncryptionContext has no key loaded for the current request.
 *
 * This means the client did not send the X-Encryption-Token header,
 * or the BootPerUserEncryption middleware was not applied to the route.
 */
final class MissingEncryptionContextException extends RuntimeException
{
    public function __construct()
    {
        parent::__construct(
            'No per-user encryption key is loaded for this request. '.
            'Ensure the X-Encryption-Token header is present and the '.
            'BootPerUserEncryption middleware is applied to this route.',
        );
    }
}
