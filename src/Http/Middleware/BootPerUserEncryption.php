<?php

declare(strict_types=1);

namespace CodeLieutenant\LaravelCrypto\Http\Middleware;

use Closure;
use CodeLieutenant\LaravelCrypto\Contracts\UserEncryptionContext;
use CodeLieutenant\LaravelCrypto\Encryption\UserKey\UserSecretManager;
use Illuminate\Auth\AuthManager;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response as SymfonyResponse;

/**
 * Reads the X-Encryption-Token header, decodes the base64url user key,
 * and loads it into UserEncryptionContext for the duration of the request.
 *
 * Register AFTER auth middleware, BEFORE any route accessing encrypted fields.
 */
final readonly class BootPerUserEncryption
{
    public const string TOKEN_HEADER = 'X-Encryption-Token';

    public function __construct(
        private UserSecretManager $manager,
        private UserEncryptionContext $context,
        private AuthManager $auth,
    ) {}

    public function handle(Request $request, Closure $next): SymfonyResponse
    {
        $user = $this->auth->user();

        if ($user === null || ! method_exists($user, 'hasUserEncryptionInitialised')) {
            return $next($request);
        }

        $rawToken = $request->header(
            (string) config('crypto.per_user.token_header', self::TOKEN_HEADER),
        );

        if ($rawToken === null || $rawToken === '') {
            return $next($request);
        }

        $key = $this->manager->decodeToken((string) $rawToken);

        if ($key === null) {
            return $next($request);
        }

        $this->context->set($key);
        sodium_memzero($key);

        try {
            return $next($request);
        } finally {
            $this->context->clear();
        }
    }
}

