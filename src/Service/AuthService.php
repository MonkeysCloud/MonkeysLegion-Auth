<?php

declare(strict_types=1);

namespace MonkeysLegion\Auth\Service;

use MonkeysLegion\Auth\Contract\AuthenticatableInterface;
use MonkeysLegion\Auth\Contract\RateLimiterInterface;
use MonkeysLegion\Auth\Contract\TokenStorageInterface;
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
use MonkeysLegion\Auth\Exception\RateLimitException;
use MonkeysLegion\Auth\Exception\TokenExpiredException;
use MonkeysLegion\Auth\Exception\TokenInvalidException;
use MonkeysLegion\Auth\Exception\TokenRevokedException;
use MonkeysLegion\Auth\Exception\TwoFactorInvalidException;
use MonkeysLegion\Auth\Exception\TwoFactorRequiredException;
use MonkeysLegion\Auth\Exception\UserAlreadyExistsException;
use PDOException;
use Psr\EventDispatcher\EventDispatcherInterface;

/**
 * Main authentication service with comprehensive security features.
 */
final class AuthService
{
    private const MAX_LOGIN_ATTEMPTS = 5;
    private const LOCKOUT_SECONDS = 900; // 15 minutes
    private const CHALLENGE_TOKEN_TTL = 300; // 5 minutes

    public function __construct(
        private UserProviderInterface $users,
        private PasswordHasher $hasher,
        private JwtService $jwt,
        private ?TokenStorageInterface $tokenStorage = null,
        private ?RateLimiterInterface $rateLimiter = null,
        private ?TwoFactorProviderInterface $twoFactor = null,
        private ?EventDispatcherInterface $events = null,
    ) {}

    /**
     * Register a new user.
     *
     * @throws UserAlreadyExistsException
     */
    public function register(
        string $email,
        string $password,
        array $attributes = [],
        ?string $ipAddress = null,
    ): AuthenticatableInterface {
        // Rate limit registration attempts
        $this->checkRateLimit("register:{$ipAddress}", 10, 3600);

        // Check if user already exists
        if ($this->users->findByEmail($email) !== null) {
            throw new UserAlreadyExistsException('Email already registered');
        }

        try {
            $user = $this->users->create(array_merge(
                [
                    'email' => $email,
                    'password_hash' => $this->hasher->hash($password),
                ],
                $attributes
            ));

            $this->dispatch(new UserRegistered($user, $ipAddress));

            return $user;
        } catch (PDOException $e) {
            // Handle race condition: user created between check and insert
            if ($e->getCode() === '23000' || (($e->errorInfo[1] ?? null) === 1062)) {
                throw new UserAlreadyExistsException('Email already registered');
            }
            throw $e;
        }
    }

    /**
     * Authenticate with email/password.
     *
     * @throws InvalidCredentialsException
     * @throws AccountLockedException
     * @throws RateLimitException
     * @throws TwoFactorRequiredException
     */
    public function login(
        string $email,
        string $password,
        ?string $ipAddress = null,
        ?string $userAgent = null,
    ): AuthResult {
        $rateLimitKey = "login:{$email}";

        // Check rate limit
        $this->checkLoginRateLimit($rateLimitKey, $email);

        // Find user
        $user = $this->users->findByEmail($email);

        if (!$user || !$this->hasher->verify($password, $user->getAuthPassword())) {
            $this->recordFailedLogin($rateLimitKey, $email, $ipAddress, $userAgent);
            throw new InvalidCredentialsException();
        }

        // Clear rate limit on success
        $this->rateLimiter?->clear($rateLimitKey);

        // Check 2FA if enabled
        if ($this->userHas2FA($user)) {
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
        // Decode challenge token
        $claims = $this->jwt->decode($challengeToken);

        if (($claims['type'] ?? '') !== '2fa_challenge') {
            throw new TokenInvalidException('Invalid challenge token');
        }

        $user = $this->users->findById($claims['sub']);
        if (!$user) {
            throw new TokenInvalidException('User not found');
        }

        // Verify 2FA code
        $secret = $this->getUserTotpSecret($user);
        if (!$secret || !$this->twoFactor?->verify($secret, $code)) {
            // Check recovery codes
            if (!$this->verifyRecoveryCode($user, $code)) {
                throw new TwoFactorInvalidException();
            }
        }

        return $this->completeLogin($user, $ipAddress, $userAgent);
    }

    /**
     * Refresh access token using refresh token.
     *
     * @throws TokenExpiredException
     * @throws TokenRevokedException
     * @throws TokenInvalidException
     */
    public function refresh(string $refreshToken, ?string $ipAddress = null): TokenPair
    {
        // Decode with extra leeway for refresh
        $claims = $this->jwt->decodeWithLeeway($refreshToken, 86400); // 24h grace

        if (($claims['type'] ?? '') !== 'refresh') {
            throw new TokenInvalidException('Not a refresh token');
        }

        $tokenId = $claims['jti'] ?? null;

        // Check if token is blacklisted
        if ($tokenId && $this->tokenStorage?->isBlacklisted($tokenId)) {
            throw new TokenRevokedException();
        }

        $userId = $claims['sub'] ?? null;
        $user = $userId ? $this->users->findById($userId) : null;

        if (!$user) {
            throw new TokenInvalidException('User not found');
        }

        // Verify token version
        $tokenVersion = $claims['ver'] ?? 0;
        if ($tokenVersion < $user->getTokenVersion()) {
            throw new TokenRevokedException('Token version mismatch');
        }

        // Rotate refresh token (blacklist old, issue new)
        if ($tokenId) {
            $this->tokenStorage?->blacklist($tokenId, $this->jwt->getRefreshTtl());
        }

        $tokens = $this->issueTokenPair($user);

        $this->dispatch(new TokenRefreshed($user->getAuthIdentifier(), $ipAddress));

        return $tokens;
    }

    /**
     * Logout - revoke tokens.
     */
    public function logout(
        string $accessToken,
        bool $allDevices = false,
        ?string $ipAddress = null,
    ): void {
        try {
            $claims = $this->jwt->decodeWithLeeway($accessToken, 3600);
            $userId = $claims['sub'] ?? null;

            if ($allDevices && $userId) {
                // Increment token version to invalidate all tokens
                $this->users->incrementTokenVersion($userId);
                $this->tokenStorage?->removeAllForUser($userId);
            } else {
                // Just blacklist current token
                $tokenId = $claims['jti'] ?? null;
                if ($tokenId) {
                    $this->tokenStorage?->blacklist($tokenId, $this->jwt->getAccessTtl());
                }
            }

            $this->dispatch(new Logout($userId ?? 0, $allDevices, $ipAddress));
        } catch (\Throwable) {
            // Token already invalid, nothing to revoke
        }
    }

    /**
     * Change password.
     */
    public function changePassword(
        AuthenticatableInterface $user,
        string $currentPassword,
        string $newPassword,
        ?string $ipAddress = null,
    ): void {
        if (!$this->hasher->verify($currentPassword, $user->getAuthPassword())) {
            throw new InvalidCredentialsException('Current password is incorrect');
        }

        // Update password
        $this->users->updatePassword(
            $user->getAuthIdentifier(),
            $this->hasher->hash($newPassword)
        );

        // Invalidate all tokens
        $this->users->incrementTokenVersion($user->getAuthIdentifier());
        $this->tokenStorage?->removeAllForUser($user->getAuthIdentifier());

        $this->dispatch(new PasswordChanged($user->getAuthIdentifier(), $ipAddress));
    }

    /**
     * Validate an access token and return claims.
     *
     * @throws TokenExpiredException
     * @throws TokenRevokedException
     * @throws TokenInvalidException
     */
    public function validateAccessToken(string $token): array
    {
        $claims = $this->jwt->decode($token);

        // Check blacklist
        $tokenId = $claims['jti'] ?? null;
        if ($tokenId && $this->tokenStorage?->isBlacklisted($tokenId)) {
            throw new TokenRevokedException();
        }

        // Verify token version
        $userId = $claims['sub'] ?? null;
        if ($userId) {
            $user = $this->users->findById($userId);
            if ($user && ($claims['ver'] ?? 0) < $user->getTokenVersion()) {
                throw new TokenRevokedException('Token version mismatch');
            }
        }

        return $claims;
    }

    /**
     * Get the current user from a token.
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

    /**
     * Issue new token pair for a user.
     */
    public function issueTokenPair(AuthenticatableInterface $user): TokenPair
    {
        $now = time();
        $userId = $user->getAuthIdentifier();
        $tokenVersion = $user->getTokenVersion();

        $accessToken = $this->jwt->issueAccessToken([
            'sub' => $userId,
            'ver' => $tokenVersion,
        ]);

        $refreshToken = $this->jwt->issueRefreshToken([
            'sub' => $userId,
            'ver' => $tokenVersion,
        ]);

        return new TokenPair(
            accessToken: $accessToken,
            refreshToken: $refreshToken,
            accessExpiresAt: $now + $this->jwt->getAccessTtl(),
            refreshExpiresAt: $now + $this->jwt->getRefreshTtl(),
        );
    }

    private function completeLogin(
        AuthenticatableInterface $user,
        ?string $ipAddress,
        ?string $userAgent,
    ): AuthResult {
        $tokens = $this->issueTokenPair($user);

        // Store refresh token if storage is available
        if ($this->tokenStorage) {
            $refreshTokenId = $this->jwt->getTokenId($tokens->refreshToken);
            if ($refreshTokenId) {
                $this->tokenStorage->store($refreshTokenId, [
                    'user_id' => $user->getAuthIdentifier(),
                    'ip' => $ipAddress,
                    'user_agent' => $userAgent,
                    'created_at' => time(),
                ], $this->jwt->getRefreshTtl());
            }
        }

        $this->dispatch(new LoginSucceeded($user, $ipAddress, $userAgent));

        return AuthResult::success($user, $tokens);
    }

    private function createChallengeToken(AuthenticatableInterface $user): string
    {
        return $this->jwt->issue([
            'sub' => $user->getAuthIdentifier(),
            'type' => '2fa_challenge',
        ], self::CHALLENGE_TOKEN_TTL);
    }

    private function checkRateLimit(string $key, int $maxAttempts, int $decaySeconds): void
    {
        if (!$this->rateLimiter) {
            return;
        }

        if (!$this->rateLimiter->attempt($key, $maxAttempts, $decaySeconds)) {
            $retryAfter = $this->rateLimiter->availableIn($key);
            throw new RateLimitException('Too many attempts', $retryAfter);
        }
    }

    private function checkLoginRateLimit(string $key, string $email): void
    {
        if (!$this->rateLimiter) {
            return;
        }

        $remaining = $this->rateLimiter->remaining($key, self::MAX_LOGIN_ATTEMPTS);

        if ($remaining <= 0) {
            $retryAfter = $this->rateLimiter->availableIn($key);
            throw new AccountLockedException(
                'Account temporarily locked due to too many failed attempts',
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

    private function userHas2FA(AuthenticatableInterface $user): bool
    {
        // Check if user has 2FA enabled
        // This would typically check a property on the user
        return method_exists($user, 'hasTwoFactorEnabled')
            && $user->hasTwoFactorEnabled();
    }

    private function getUserTotpSecret(AuthenticatableInterface $user): ?string
    {
        return method_exists($user, 'getTwoFactorSecret')
            ? $user->getTwoFactorSecret()
            : null;
    }

    private function verifyRecoveryCode(AuthenticatableInterface $user, string $code): bool
    {
        // This would check against stored recovery codes
        // Implementation depends on how recovery codes are stored
        return false;
    }

    private function dispatch(object $event): void
    {
        $this->events?->dispatch($event);
    }
}
