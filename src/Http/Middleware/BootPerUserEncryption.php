<?php

declare(strict_types=1);

namespace CodeLieutenant\LaravelCrypto\Http\Middleware;

use Closure;
use CodeLieutenant\LaravelCrypto\Contracts\UserEncryptionContext;
use CodeLieutenant\LaravelCrypto\Encryption\UserKey\UserSecretManager;
use Illuminate\Auth\AuthManager;
use Illuminate\Contracts\Config\Repository as Config;
use Illuminate\Contracts\Encryption\Encrypter as LaravelEncrypter;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Cookie;
use Symfony\Component\HttpFoundation\Response as SymfonyResponse;
use Throwable;

/**
 * Boots the per-user encryption context for the current request.
 *
 * ## Token transport — priority order (read)
 *
 *  1. X-Encryption-Token **header**  (API / SPA clients)
 *  2. `enc_token` **HTTP-only cookie** (web / browser clients)
 *  3. Auto-derive / auto-enroll  (fallback — no client input needed)
 *
 * ## Token transport — write
 *
 * Whenever a token is issued (paths 2/3), it is written to **both** the
 * response header AND the cookie so that SPA and web clients are both served
 * from the same middleware.
 *
 * The cookie value can optionally be encrypted with Laravel's default encrypter
 * (APP_KEY) via `crypto.per_user.cookie_encrypt = true` (default on).  This
 * means the encryption key is encrypted-at-rest inside an HTTP-only cookie that
 * JavaScript cannot read — as secure as a session token.
 *
 * ## Code-paths (fallback)
 *
 * 3a. **No token + server-wrapped blob** — re-derive key from BLAKE2b(appKey, userId).
 * 3b. **No token + no blob** — auto-enroll: generate server-wrapped blob, persist.
 *
 * Register AFTER auth middleware, BEFORE any route that accesses encrypted fields.
 */
final readonly class BootPerUserEncryption
{
    public const string TOKEN_HEADER = 'X-Encryption-Token';

    public const string COOKIE_NAME = 'enc_token';

    public function __construct(
        private UserSecretManager $manager,
        private UserEncryptionContext $context,
        private AuthManager $auth,
        private Config $config,
        private LaravelEncrypter $encrypter,
    ) {}

    public function handle(Request $request, Closure $next): SymfonyResponse
    {
        $user = $this->auth->user();

        if ($user === null || ! method_exists($user, 'hasUserEncryptionInitialised')) {
            return $next($request);
        }

        $headerName = (string) $this->config->get('crypto.per_user.token_header', self::TOKEN_HEADER);
        $cookieName = $this->config->get('crypto.per_user.cookie_name', self::COOKIE_NAME);

        // ── Priority 1: header (SPA / API) ───────────────────────────────────
        $rawToken = $request->header($headerName);
        if ($rawToken !== null && $rawToken !== '') {
            $key = $this->manager->decodeToken((string) $rawToken);
            if ($key !== null) {
                return $this->runWithKey($key, $request, $next);
            }
        }

        // ── Priority 2: HTTP-only cookie (web / browser) ─────────────────────
        if ($cookieName !== null) {
            $cookieToken = $this->readCookieToken($request, (string) $cookieName);
            if ($cookieToken !== null) {
                $key = $this->manager->decodeToken($cookieToken);
                if ($key !== null) {
                    return $this->runWithKey($key, $request, $next);
                }
            }
        }

        // ── Priority 3: auto-derive / auto-enroll ────────────────────────────
        $appKey = $this->resolveAppKey();
        $userId = (string) $user->getAuthIdentifier();
        $blob = method_exists($user, 'getRawEncryptionKeyBlob') ? $user->getRawEncryptionKeyBlob() : null;

        if ($blob !== null && $this->manager->isServerWrapped($blob)) {
            // 3a — re-derive
            $key = $this->manager->unwrapServerBlob($appKey, $userId, $blob);
            $newToken = $this->manager->encodeToken($key);
        } else {
            // 3b — auto-enroll
            $result = $this->manager->generateServerWrapped($appKey, $userId);
            $key = $result['key'];
            $newToken = $this->manager->encodeToken($key);

            if (method_exists($user, 'setAttribute')) {
                $user->setAttribute('encryption_key', $result['blob']);
                $user->save(); // @phpstan-ignore-line
            }
        }

        sodium_memzero($appKey);
        $this->context->set($key);
        sodium_memzero($key);

        try {
            $response = $next($request);
        } finally {
            $this->context->clear();
        }

        // Write token to both header and cookie
        $response->headers->set($headerName, $newToken);

        if ($cookieName !== null) {
            $response->headers->setCookie($this->buildCookie((string) $cookieName, $newToken));
        }

        return $response;
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Helpers
    // ─────────────────────────────────────────────────────────────────────────

    private function runWithKey(string $key, Request $request, Closure $next): SymfonyResponse
    {
        $this->context->set($key);
        sodium_memzero($key);

        try {
            return $next($request);
        } finally {
            $this->context->clear();
        }
    }

    /**
     * Read and optionally decrypt the token from the request cookie.
     * Returns null if the cookie is absent, tampered, or cannot be decoded.
     */
    private function readCookieToken(Request $request, string $cookieName): ?string
    {
        $raw = $request->cookie($cookieName);

        if ($raw === null || $raw === '') {
            return null;
        }

        $raw = (string) $raw;

        if (! $this->config->get('crypto.per_user.cookie_encrypt', true)) {
            return $raw;
        }

        try {
            $decrypted = $this->encrypter->decryptString($raw);

            return $decrypted !== '' ? $decrypted : null;
        } catch (Throwable) {
            // Tampered or from a different app key — ignore
            return null;
        }
    }

    /**
     * Build the secure HTTP-only cookie carrying the encryption token.
     */
    private function buildCookie(string $cookieName, string $token): Cookie
    {
        $value = $this->config->get('crypto.per_user.cookie_encrypt', true)
            ? $this->encrypter->encryptString($token)
            : $token;

        $ttl = (int) $this->config->get('crypto.per_user.cookie_ttl', 120);
        $secure = (bool) $this->config->get('crypto.per_user.cookie_secure', false);
        $sameSite = (string) $this->config->get('crypto.per_user.cookie_same_site', 'lax');

        return Cookie::create(
            name: $cookieName,
            value: $value,
            expire: $ttl > 0 ? now()->addMinutes($ttl) : 0,
            secure: $secure,
            sameSite: $sameSite,
        );
    }

    /**
     * Resolve the raw 32-byte app key, stripping the 'base64:' prefix.
     */
    private function resolveAppKey(): string
    {
        $key = (string) $this->config->get('app.key', '');

        if (str_starts_with($key, 'base64:')) {
            $decoded = base64_decode(substr($key, 7), true);

            return $decoded !== false ? $decoded : $key;
        }

        return $key;
    }
}
