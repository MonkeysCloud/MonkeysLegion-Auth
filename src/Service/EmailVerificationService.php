<?php

declare(strict_types=1);

namespace MonkeysLegion\Auth\Service;

use MonkeysLegion\Auth\Contract\UserProviderInterface;
use MonkeysLegion\Auth\Exception\TokenExpiredException;
use MonkeysLegion\Auth\Exception\TokenInvalidException;
use Psr\EventDispatcher\EventDispatcherInterface;

/**
 * Service for email verification functionality.
 */
final class EmailVerificationService
{
    private const TOKEN_TTL = 86400; // 24 hours

    public function __construct(
        private UserProviderInterface $users,
        private JwtService $jwt,
        private ?EventDispatcherInterface $events = null,
    ) {}

    /**
     * Create an email verification token.
     */
    public function createVerificationToken(int|string $userId, string $email): string
    {
        return $this->jwt->issue([
            'sub' => $userId,
            'email' => $email,
            'type' => 'email_verification',
        ], self::TOKEN_TTL);
    }

    /**
     * Verify an email verification token.
     *
     * @return array{user_id: int|string, email: string}
     * @throws TokenExpiredException
     * @throws TokenInvalidException
     */
    public function verify(string $token): array
    {
        $claims = $this->jwt->decode($token);

        if (($claims['type'] ?? '') !== 'email_verification') {
            throw new TokenInvalidException('Invalid verification token');
        }

        $userId = $claims['sub'] ?? null;
        $email = $claims['email'] ?? null;

        if (!$userId || !$email) {
            throw new TokenInvalidException('Invalid token payload');
        }

        $user = $this->users->findById($userId);

        if (!$user) {
            throw new TokenInvalidException('User not found');
        }

        return [
            'user_id' => $userId,
            'email' => $email,
        ];
    }

    /**
     * Generate a verification URL.
     */
    public function generateVerificationUrl(string $token, string $baseUrl): string
    {
        return rtrim($baseUrl, '/') . '?' . http_build_query(['token' => $token]);
    }
}
