<?php

declare(strict_types=1);

/**
 * MonkeysLegion Auth v2
 *
 * @package   MonkeysLegion\Auth
 * @author    MonkeysCloud <jorge@monkeyscloud.com>
 * @license   MIT
 *
 * @requires  PHP 8.4
 */

namespace MonkeysLegion\Auth\Service;

use MonkeysLegion\Auth\Contract\AuthenticatableInterface;
use MonkeysLegion\Auth\Contract\RateLimiterInterface;
use MonkeysLegion\Auth\Contract\TokenStorageInterface;
use MonkeysLegion\Auth\Contract\TwoFactorAuthenticatable;
use MonkeysLegion\Auth\Contract\TwoFactorProviderInterface;
use MonkeysLegion\Auth\Contract\UserProviderInterface;
use MonkeysLegion\Auth\DTO\AuthResult;
use MonkeysLegion\Auth\DTO\TokenPair;
use MonkeysLegion\Auth\Event\LoginFailed;
use MonkeysLegion\Auth\Event\LoginSucceeded;
use MonkeysLegion\Auth\Event\Logout;
use MonkeysLegion\Auth\Event\PasswordChanged;
use MonkeysLegion\Auth\Event\TokenRefreshed;
use MonkeysLegion\Auth\Event\UserRegistered;
use MonkeysLegion\Auth\Exception\AccountLockedException;
use MonkeysLegion\Auth\Exception\InvalidCredentialsException;
use MonkeysLegion\Auth\Exception\RateLimitExceededException;
use MonkeysLegion\Auth\Exception\TokenExpiredException;
use MonkeysLegion\Auth\Exception\TokenInvalidException;
use MonkeysLegion\Auth\Exception\TokenRevokedException;
use MonkeysLegion\Auth\Exception\TwoFactorInvalidException;
use MonkeysLegion\Auth\Exception\TwoFactorRequiredException;
use MonkeysLegion\Auth\Exception\UserAlreadyExistsException;
use Psr\EventDispatcher\EventDispatcherInterface;

/**
 * Core authentication service — guard-agnostic credential-based auth.
 *
 * SECURITY:
 * - Rate limiting on login/register to prevent brute-force
 * - Token versioning for global invalidation
 * - Refresh token family tracking detects reuse attacks
 * - 2FA challenge token has short TTL (5 min)
 *
 * Uses PHP 8.4: property hooks.
 */
final class AuthService
{
    private const int MAX_LOGIN_ATTEMPTS = 5;
    private const int LOCKOUT_SECONDS    = 900;   // 15 minutes
    private const int CHALLENGE_TOKEN_TTL = 300;  // 5 minutes

    public function __construct(
        private readonly UserProviderInterface $users,
        private readonly PasswordHasher $hasher,
        private readonly JwtService $jwt,
        private readonly ?TokenStorageInterface $tokenStorage = null,
        private readonly ?RateLimiterInterface $rateLimiter = null,
        private readonly ?TwoFactorProviderInterface $twoFactor = null,
        private readonly ?EventDispatcherInterface $events = null,
    ) {}

    // ── Registration ───────────────────────────────────────────

    /**
     * Register a new user.
     *
     * @param array<string, mixed> $attributes Extra user attributes.
     * @throws UserAlreadyExistsException
     * @throws RateLimitExceededException
     */
    public function register(
        string $email,
        string $password,
        array $attributes = [],
        ?string $ipAddress = null,
    ): AuthenticatableInterface {
        $this->checkRateLimit("register:{$ipAddress}", 10, 3600);

        if ($this->users->findByEmail($email) !== null) {
            throw new UserAlreadyExistsException();
        }

        try {
            $user = $this->users->create(array_merge([
                'email'         => $email,
                'password_hash' => $this->hasher->hash($password),
            ], $attributes));

            $this->dispatch(new UserRegistered($user, $ipAddress));

            return $user;
        } catch (\PDOException $e) {
            // Race condition: user created between check and insert
            if ($e->getCode() === '23000' || (($e->errorInfo[1] ?? null) === 1062)) {
                throw new UserAlreadyExistsException();
            }
            throw $e;
        }
    }

    // ── Login ──────────────────────────────────────────────────

    /**
     * Authenticate with email and password.
     *
     * @throws InvalidCredentialsException
     * @throws AccountLockedException
     * @throws RateLimitExceededException
     */
    public function login(
        string $email,
        string $password,
        ?string $ipAddress = null,
        ?string $userAgent = null,
    ): AuthResult {
        $rateLimitKey = "login:{$email}";

        $this->checkLoginRateLimit($rateLimitKey);

        $user = $this->users->findByEmail($email);

        if ($user === null || !$this->hasher->verify($password, $user->getAuthPassword())) {
            $this->recordFailedLogin($rateLimitKey, $email, $ipAddress, $userAgent);
            throw new InvalidCredentialsException();
        }

        // Rehash if needed (algorithm/cost upgrade)
        if ($this->hasher->needsRehash($user->getAuthPassword())) {
            $this->users->updatePassword(
                $user->getAuthIdentifier(),
                $this->hasher->hash($password),
            );
        }

        // Clear rate limit on success
        $this->rateLimiter?->clear($rateLimitKey);

        // Check 2FA
        if ($user instanceof TwoFactorAuthenticatable && $user->hasTwoFactorEnabled()) {
            $challengeToken = $this->createChallengeToken($user);
            return AuthResult::requires2FA($challengeToken);
        }

        return $this->completeLogin($user, $ipAddress, $userAgent);
    }

    /**
     * Complete login after 2FA verification.
     *
     * @throws TwoFactorInvalidException
     * @throws TokenInvalidException
     */
    public function verify2FA(
        string $challengeToken,
        string $code,
        ?string $ipAddress = null,
        ?string $userAgent = null,
    ): AuthResult {
        $claims = $this->jwt->decode($challengeToken);

        if (($claims['type'] ?? '') !== '2fa_challenge') {
            throw new TokenInvalidException('Invalid challenge token.');
        }

        $user = $this->users->findById($claims['sub']);
        if ($user === null) {
            throw new TokenInvalidException('User not found.');
        }

        // Verify TOTP code
        if ($user instanceof TwoFactorAuthenticatable) {
            $secret = $user->getTwoFactorSecret();
            if ($secret !== null && $this->twoFactor?->verify($secret, $code)) {
                return $this->completeLogin($user, $ipAddress, $userAgent);
            }

            // Try recovery codes
            if ($this->verifyRecoveryCode($user, $code)) {
                return $this->completeLogin($user, $ipAddress, $userAgent);
            }
        }

        throw new TwoFactorInvalidException();
    }

    // ── Token Management ───────────────────────────────────────

    /**
     * Refresh an access token using a refresh token.
     *
     * SECURITY: Implements token family rotation — detects reuse attacks.
     *
     * @throws TokenExpiredException
     * @throws TokenRevokedException
     * @throws TokenInvalidException
     */
    public function refresh(string $refreshToken, ?string $ipAddress = null): TokenPair
    {
        $claims = $this->jwt->decodeWithLeeway($refreshToken, 86400);

        if (($claims['type'] ?? '') !== 'refresh') {
            throw new TokenInvalidException('Not a refresh token.');
        }

        $tokenId = $claims['jti'] ?? null;

        // Check blacklist
        if ($tokenId !== null && $this->tokenStorage?->isBlacklisted($tokenId)) {
            // SECURITY: If a blacklisted refresh token is reused, the entire
            // token family may be compromised. Invalidate all user tokens.
            $userId = $claims['sub'] ?? null;
            if ($userId !== null) {
                $this->users->incrementTokenVersion($userId);
                $this->tokenStorage->removeAllForUser($userId);
            }
            throw new TokenRevokedException('Token reuse detected.');
        }

        $userId = $claims['sub'] ?? null;
        $user   = $userId !== null ? $this->users->findById($userId) : null;

        if ($user === null) {
            throw new TokenInvalidException('User not found.');
        }

        // Verify token version
        if (($claims['ver'] ?? 0) < $user->getTokenVersion()) {
            throw new TokenRevokedException('Token version mismatch.');
        }

        // Rotate: blacklist old, issue new (same family)
        if ($tokenId !== null) {
            $this->tokenStorage?->blacklist($tokenId, $this->jwt->refreshTtl);
        }

        $familyId = $claims['family'] ?? null;
        $tokens   = $this->issueTokenPair($user, $familyId);

        $this->dispatch(new TokenRefreshed($user->getAuthIdentifier(), $ipAddress));

        return $tokens;
    }

    /**
     * Validate an access token and return claims.
     *
     * @return array<string, mixed>
     * @throws TokenExpiredException
     * @throws TokenRevokedException
     * @throws TokenInvalidException
     */
    public function validateAccessToken(string $token): array
    {
        $claims = $this->jwt->decode($token);

        $tokenId = $claims['jti'] ?? null;
        if ($tokenId !== null && $this->tokenStorage?->isBlacklisted($tokenId)) {
            throw new TokenRevokedException();
        }

        $userId = $claims['sub'] ?? null;
        if ($userId !== null) {
            $user = $this->users->findById($userId);
            if ($user !== null && ($claims['ver'] ?? 0) < $user->getTokenVersion()) {
                throw new TokenRevokedException('Token version mismatch.');
            }
        }

        return $claims;
    }

    /**
     * Get user from an access token.
     */
    public function getUserFromToken(string $token): ?AuthenticatableInterface
    {
        try {
            $claims = $this->validateAccessToken($token);
            return $this->users->findById($claims['sub'] ?? 0);
        } catch (\Throwable) {
            return null;
        }
    }

    // ── Logout ─────────────────────────────────────────────────

    /**
     * Logout — revoke tokens.
     *
     * @param bool $allDevices If true, invalidate ALL tokens via version increment.
     */
    public function logout(
        string $accessToken,
        bool $allDevices = false,
        ?string $ipAddress = null,
    ): void {
        try {
            $claims = $this->jwt->decodeWithLeeway($accessToken, 3600);
            $userId = $claims['sub'] ?? null;

            if ($allDevices && $userId !== null) {
                $this->users->incrementTokenVersion($userId);
                $this->tokenStorage?->removeAllForUser($userId);
            } else {
                $tokenId = $claims['jti'] ?? null;
                if ($tokenId !== null) {
                    $this->tokenStorage?->blacklist($tokenId, $this->jwt->accessTtl);
                }
            }

            $this->dispatch(new Logout($userId ?? 0, $allDevices, $ipAddress));
        } catch (\Throwable) {
            // Token already invalid — nothing to revoke
        }
    }

    // ── Password Management ────────────────────────────────────

    /**
     * Change user's password.
     *
     * SECURITY: Invalidates all tokens after password change.
     */
    public function changePassword(
        AuthenticatableInterface $user,
        string $currentPassword,
        string $newPassword,
        ?string $ipAddress = null,
    ): void {
        if (!$this->hasher->verify($currentPassword, $user->getAuthPassword())) {
            throw new InvalidCredentialsException('Current password is incorrect.');
        }

        $this->users->updatePassword(
            $user->getAuthIdentifier(),
            $this->hasher->hash($newPassword),
        );

        // Invalidate all tokens
        $this->users->incrementTokenVersion($user->getAuthIdentifier());
        $this->tokenStorage?->removeAllForUser($user->getAuthIdentifier());

        $this->dispatch(new PasswordChanged($user->getAuthIdentifier(), $ipAddress));
    }

    // ── Token Issuance ─────────────────────────────────────────

    /**
     * Issue a new token pair (access + refresh) for a user.
     */
    public function issueTokenPair(
        AuthenticatableInterface $user,
        ?string $familyId = null,
    ): TokenPair {
        $now          = time();
        $userId       = $user->getAuthIdentifier();
        $tokenVersion = $user->getTokenVersion();

        $accessToken = $this->jwt->issueAccessToken([
            'sub' => $userId,
            'ver' => $tokenVersion,
        ]);

        $refreshToken = $this->jwt->issueRefreshToken([
            'sub' => $userId,
            'ver' => $tokenVersion,
        ], $familyId);

        return new TokenPair(
            accessToken: $accessToken,
            refreshToken: $refreshToken,
            accessExpiresAt: $now + $this->jwt->accessTtl,
            refreshExpiresAt: $now + $this->jwt->refreshTtl,
            familyId: $familyId,
        );
    }

    // ── Private Helpers ────────────────────────────────────────

    private function completeLogin(
        AuthenticatableInterface $user,
        ?string $ipAddress,
        ?string $userAgent,
    ): AuthResult {
        $tokens = $this->issueTokenPair($user);

        // Store refresh token metadata
        if ($this->tokenStorage !== null) {
            $refreshTokenId = $this->jwt->getTokenId($tokens->refreshToken);
            if ($refreshTokenId !== null) {
                $this->tokenStorage->store($refreshTokenId, [
                    'user_id'    => $user->getAuthIdentifier(),
                    'ip'         => $ipAddress,
                    'user_agent' => $userAgent,
                    'created_at' => time(),
                ], $this->jwt->refreshTtl);
            }
        }

        $this->dispatch(new LoginSucceeded($user, $ipAddress, $userAgent));

        return AuthResult::success($user, $tokens, 'jwt');
    }

    private function createChallengeToken(AuthenticatableInterface $user): string
    {
        return $this->jwt->issue([
            'sub'  => $user->getAuthIdentifier(),
            'type' => '2fa_challenge',
        ], self::CHALLENGE_TOKEN_TTL);
    }

    private function checkRateLimit(string $key, int $maxAttempts, int $decaySeconds): void
    {
        if ($this->rateLimiter === null) {
            return;
        }

        if (!$this->rateLimiter->attempt($key, $maxAttempts, $decaySeconds)) {
            $retryAfter = $this->rateLimiter->availableIn($key);
            throw new RateLimitExceededException('Too many attempts.', $retryAfter);
        }
    }

    private function checkLoginRateLimit(string $key): void
    {
        if ($this->rateLimiter === null) {
            return;
        }

        $remaining = $this->rateLimiter->remaining($key, self::MAX_LOGIN_ATTEMPTS);

        if ($remaining <= 0) {
            $retryAfter = $this->rateLimiter->availableIn($key);
            throw new AccountLockedException(
                'Account temporarily locked due to too many failed attempts.',
                time() + $retryAfter,
            );
        }
    }

    private function recordFailedLogin(
        string $key,
        string $email,
        ?string $ipAddress,
        ?string $userAgent,
    ): void {
        $this->rateLimiter?->hit($key, self::LOCKOUT_SECONDS);
        $this->dispatch(new LoginFailed($email, 'Invalid credentials', $ipAddress, $userAgent));
    }

    private function verifyRecoveryCode(object $user, string $code): bool
    {
        if (!$user instanceof TwoFactorAuthenticatable) {
            return false;
        }

        $codes = $user->getRecoveryCodes();
        foreach ($codes as $hashedCode) {
            if (hash_equals($hashedCode, hash('sha256', strtoupper(trim($code))))) {
                // Remove used recovery code
                $remaining = array_filter($codes, fn(string $c) => $c !== $hashedCode);
                $user->setRecoveryCodes(array_values($remaining));
                return true;
            }
        }

        return false;
    }

    private function dispatch(object $event): void
    {
        $this->events?->dispatch($event);
    }
}
