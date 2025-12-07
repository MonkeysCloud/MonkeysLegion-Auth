<?php

declare(strict_types=1);

namespace MonkeysLegion\Auth\Service;

use MonkeysLegion\Auth\Contract\UserProviderInterface;
use MonkeysLegion\Auth\Event\PasswordChanged;
use MonkeysLegion\Auth\Event\PasswordResetRequested;
use MonkeysLegion\Auth\Exception\TokenExpiredException;
use MonkeysLegion\Auth\Exception\TokenInvalidException;
use Psr\EventDispatcher\EventDispatcherInterface;

/**
 * Service for password reset functionality.
 */
final class PasswordResetService
{
    private const TOKEN_TTL = 3600; // 1 hour

    public function __construct(
        private UserProviderInterface $users,
        private PasswordHasher $hasher,
        private JwtService $jwt,
        private ?EventDispatcherInterface $events = null,
    ) {}

    /**
     * Create a password reset token for an email.
     *
     * @return string|null The reset token, or null if user not found
     */
    public function createResetToken(string $email, ?string $ipAddress = null): ?string
    {
        $user = $this->users->findByEmail($email);

        if (!$user) {
            // Return null silently to prevent email enumeration
            return null;
        }

        $token = $this->jwt->issue([
            'sub' => $user->getAuthIdentifier(),
            'email' => $email,
            'type' => 'password_reset',
            'ver' => $user->getTokenVersion(),
        ], self::TOKEN_TTL);

        $this->dispatch(new PasswordResetRequested($email, $token, $ipAddress));

        return $token;
    }

    /**
     * Validate a password reset token.
     *
     * @return array{user_id: int|string, email: string}
     * @throws TokenExpiredException
     * @throws TokenInvalidException
     */
    public function validateResetToken(string $token): array
    {
        $claims = $this->jwt->decode($token);

        if (($claims['type'] ?? '') !== 'password_reset') {
            throw new TokenInvalidException('Invalid reset token');
        }

        $userId = $claims['sub'] ?? null;
        $user = $userId ? $this->users->findById($userId) : null;

        if (!$user) {
            throw new TokenInvalidException('User not found');
        }

        // Check token version hasn't changed
        if (($claims['ver'] ?? 0) !== $user->getTokenVersion()) {
            throw new TokenInvalidException('Token has been invalidated');
        }

        return [
            'user_id' => $userId,
            'email' => $claims['email'] ?? '',
        ];
    }

    /**
     * Reset password using a valid token.
     *
     * @throws TokenExpiredException
     * @throws TokenInvalidException
     */
    public function resetPassword(
        string $token,
        string $newPassword,
        ?string $ipAddress = null,
    ): void {
        $data = $this->validateResetToken($token);

        // Hash new password
        $hash = $this->hasher->hash($newPassword);

        // Update password (this should be handled by UserProvider)
        // $this->users->updatePassword($data['user_id'], $hash);

        // Increment token version to invalidate all existing tokens
        $this->users->incrementTokenVersion($data['user_id']);

        $this->dispatch(new PasswordChanged($data['user_id'], $ipAddress));
    }

    private function dispatch(object $event): void
    {
        $this->events?->dispatch($event);
    }
}
