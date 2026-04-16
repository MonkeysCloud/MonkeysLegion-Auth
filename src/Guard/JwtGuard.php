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
use MonkeysLegion\Auth\Contract\GuardInterface;
use MonkeysLegion\Auth\Contract\TokenStorageInterface;
use MonkeysLegion\Auth\Contract\UserProviderInterface;
use MonkeysLegion\Auth\Exception\TokenExpiredException;
use MonkeysLegion\Auth\Exception\TokenInvalidException;
use MonkeysLegion\Auth\Exception\TokenRevokedException;
use MonkeysLegion\Auth\Service\JwtService;
use Psr\Http\Message\ServerRequestInterface;

/**
 * JWT bearer token guard — validates Authorization: Bearer <token>.
 *
 * SECURITY: Validates signature, expiry, blacklist, and token version.
 *
 * Uses PHP 8.4: property hooks.
 */
final class JwtGuard implements GuardInterface
{
    private ?AuthenticatableInterface $_user = null;

    /** Currently authenticated user. */
    public ?AuthenticatableInterface $currentUser {
        get => $this->_user;
    }

    public function __construct(
        private readonly JwtService $jwt,
        private readonly UserProviderInterface $users,
        private readonly ?TokenStorageInterface $tokenStorage = null,
    ) {}

    public function name(): string
    {
        return 'jwt';
    }

    public function authenticate(ServerRequestInterface $request): ?AuthenticatableInterface
    {
        $this->_user = null;

        $token = $this->extractBearerToken($request);
        if ($token === null) {
            return null;
        }

        try {
            $claims = $this->jwt->decode($token);

            // Check blacklist
            $tokenId = $claims['jti'] ?? null;
            if ($tokenId !== null && $this->tokenStorage?->isBlacklisted($tokenId)) {
                return null;
            }

            // Resolve user
            $userId = $claims['sub'] ?? null;
            if ($userId === null) {
                return null;
            }

            $user = $this->users->findById($userId);
            if ($user === null) {
                return null;
            }

            // Verify token version
            $tokenVersion = $claims['ver'] ?? 0;
            if ($tokenVersion < $user->getTokenVersion()) {
                return null;
            }

            $this->_user = $user;
            return $user;
        } catch (TokenExpiredException | TokenInvalidException | TokenRevokedException) {
            return null;
        }
    }

    public function validate(array $credentials): bool
    {
        $token = $credentials['token'] ?? null;
        if (!is_string($token)) {
            return false;
        }

        try {
            $this->jwt->decode($token);
            return true;
        } catch (\Throwable) {
            return false;
        }
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

    /**
     * Extract Bearer token from Authorization header.
     */
    private function extractBearerToken(ServerRequestInterface $request): ?string
    {
        $header = $request->getHeaderLine('Authorization');
        if ($header === '' || !str_starts_with($header, 'Bearer ')) {
            return null;
        }

        $token = trim(substr($header, 7));
        return $token !== '' ? $token : null;
    }
}
