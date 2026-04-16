<?php

declare(strict_types=1);

/**
 * MonkeysLegion Auth v2
 *
 * @package   MonkeysLegion\Auth
 * @author    MonkeysCloud <jorge@monkeys.cloud>
 * @license   MIT
 *
 * @requires  PHP 8.4
 */

namespace MonkeysLegion\Auth\Guard;

use MonkeysLegion\Auth\Contract\AuthenticatableInterface;
use MonkeysLegion\Auth\Contract\SessionInterface;
use MonkeysLegion\Auth\Contract\StatefulGuardInterface;
use MonkeysLegion\Auth\Contract\UserProviderInterface;
use Psr\Http\Message\ServerRequestInterface;

/**
 * Session-based guard — stores authenticated user ID in the session.
 *
 * SECURITY:
 * - Regenerates session ID on login (prevents session fixation)
 * - Clears session on logout (prevents session replay)
 * - Validates token version for global invalidation
 * - Optional remember-me via cookie token
 *
 * Uses PHP 8.4: property hooks.
 */
final class SessionGuard implements StatefulGuardInterface
{
    private const string SESSION_KEY  = '_ml_auth_id';
    private const string VERSION_KEY  = '_ml_auth_ver';
    private const string REMEMBER_KEY = '_ml_remember';

    private ?AuthenticatableInterface $_user = null;
    private bool $viaRememberCookie = false;

    /** Currently authenticated user. */
    public ?AuthenticatableInterface $currentUser {
        get => $this->_user;
    }

    public function __construct(
        private readonly SessionInterface $session,
        private readonly UserProviderInterface $users,
    ) {}

    // ── GuardInterface ─────────────────────────────────────────

    public function name(): string
    {
        return 'session';
    }

    /**
     * Authenticate from the session or remember-me token.
     */
    public function authenticate(ServerRequestInterface $request): ?AuthenticatableInterface
    {
        // Already resolved this request
        if ($this->_user !== null) {
            return $this->_user;
        }

        // Try session first
        if ($this->session->has(self::SESSION_KEY)) {
            $userId = $this->session->get(self::SESSION_KEY);
            $user   = $this->users->findById($userId);

            if ($user !== null) {
                // Validate token version for global invalidation
                $storedVersion = (int) $this->session->get(self::VERSION_KEY, 0);
                if ($storedVersion >= $user->getTokenVersion()) {
                    $this->_user = $user;
                    return $user;
                }

                // Version mismatch — session invalidated globally
                $this->session->forget(self::SESSION_KEY);
                $this->session->forget(self::VERSION_KEY);
            }
        }

        // Try remember-me cookie (format: "userId|token")
        $cookies = $request->getCookieParams();
        $rememberValue = $cookies[self::REMEMBER_KEY] ?? null;

        if (is_string($rememberValue) && str_contains($rememberValue, '|')) {
            [$userId, $rememberToken] = explode('|', $rememberValue, 2);
            $user = $this->users->findByRememberToken($userId, $rememberToken);
            if ($user !== null) {
                $this->login($user, false);
                $this->viaRememberCookie = true;
                return $user;
            }
        }

        return null;
    }

    public function validate(array $credentials): bool
    {
        $email    = $credentials['email'] ?? null;
        $password = $credentials['password'] ?? null;

        if (!is_string($email) || !is_string($password)) {
            return false;
        }

        $user = $this->users->findByEmail($email);
        if ($user === null) {
            return false;
        }

        return password_verify($password, $user->getAuthPassword());
    }

    public function user(): ?AuthenticatableInterface
    {
        return $this->_user;
    }

    public function id(): int|string|null
    {
        return $this->_user?->getAuthIdentifier();
    }

    public function check(): bool
    {
        return $this->_user !== null;
    }

    public function guest(): bool
    {
        return $this->_user === null;
    }

    // ── StatefulGuardInterface ──────────────────────────────────

    /**
     * Log a user in via the session.
     *
     * SECURITY: Regenerates session ID to prevent fixation attacks.
     * If $remember is true, generates a remember token and persists it.
     */
    public function login(AuthenticatableInterface $user, bool $remember = false): void
    {
        // Regenerate session to prevent fixation
        $this->session->regenerate(true);

        $this->session->put(self::SESSION_KEY, $user->getAuthIdentifier());
        $this->session->put(self::VERSION_KEY, $user->getTokenVersion());
        $this->_user = $user;

        // Generate and persist remember-me token
        if ($remember) {
            $token = bin2hex(random_bytes(32));
            $this->users->updateRememberToken(
                $user->getAuthIdentifier(),
                $token,
            );
            // The remember cookie value is set by the caller (middleware/controller)
            // via: setcookie(self::REMEMBER_KEY, "{$userId}|{$token}", ...)
            $this->session->put(self::REMEMBER_KEY, $user->getAuthIdentifier() . '|' . $token);
        }
    }

    /**
     * Log a user in by their identifier.
     */
    public function loginUsingId(int|string $id, bool $remember = false): ?AuthenticatableInterface
    {
        $user = $this->users->findById($id);
        if ($user === null) {
            return null;
        }

        $this->login($user, $remember);
        return $user;
    }

    /**
     * Log out — clear session and optionally the remember token.
     */
    public function logout(): void
    {
        // Clear remember token if user is logged in
        if ($this->_user !== null) {
            $this->users->updateRememberToken(
                $this->_user->getAuthIdentifier(),
                null,
            );
        }

        $this->session->forget(self::SESSION_KEY);
        $this->session->forget(self::VERSION_KEY);
        $this->session->forget(self::REMEMBER_KEY);
        $this->session->regenerate(true);

        $this->_user = null;
        $this->viaRememberCookie = false;
    }

    /**
     * Whether the user was authenticated via remember-me cookie.
     */
    public function viaRemember(): bool
    {
        return $this->viaRememberCookie;
    }
}
