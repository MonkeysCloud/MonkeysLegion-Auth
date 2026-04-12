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

namespace MonkeysLegion\Auth\Storage;

use MonkeysLegion\Auth\Contract\AuthenticatableInterface;
use MonkeysLegion\Auth\Contract\UserProviderInterface;

/**
 * In-memory user provider — for testing.
 */
final class InMemoryUserProvider implements UserProviderInterface
{
    /** @var array<int|string, AuthenticatableInterface> */
    private array $users = [];

    /** @var array<string, int|string> Email → user ID */
    private array $emailIndex = [];

    /** @var array<string, int|string> API key → user ID */
    private array $apiKeyIndex = [];

    public function addUser(AuthenticatableInterface $user): void
    {
        $id = $user->getAuthIdentifier();
        $this->users[$id] = $user;

        // Index by email if available via reflection
        $email = $this->extractEmail($user);
        if ($email !== null) {
            $this->emailIndex[$email] = $id;
        }
    }

    public function addApiKey(int|string $userId, string $key): void
    {
        $this->apiKeyIndex[$key] = $userId;
    }

    public function findById(int|string $id): ?AuthenticatableInterface
    {
        return $this->users[$id] ?? null;
    }

    public function findByEmail(string $email): ?AuthenticatableInterface
    {
        $id = $this->emailIndex[$email] ?? null;
        return $id !== null ? ($this->users[$id] ?? null) : null;
    }

    public function findByRememberToken(int|string $id, string $token): ?AuthenticatableInterface
    {
        $user = $this->users[$id] ?? null;
        if ($user !== null && $user->getRememberToken() === $token) {
            return $user;
        }
        return null;
    }

    public function findByApiKey(string $key): ?AuthenticatableInterface
    {
        $id = $this->apiKeyIndex[$key] ?? null;
        return $id !== null ? ($this->users[$id] ?? null) : null;
    }

    public function create(array $attributes): AuthenticatableInterface
    {
        throw new \RuntimeException('InMemoryUserProvider::create() not supported. Use addUser().');
    }

    public function updatePassword(int|string $id, string $hashedPassword): void
    {
        // No-op for in-memory
    }

    public function incrementTokenVersion(int|string $id): void
    {
        // No-op for in-memory
    }

    public function updateRememberToken(int|string $id, string $token): void
    {
        $user = $this->users[$id] ?? null;
        $user?->setRememberToken($token);
    }

    private function extractEmail(object $user): ?string
    {
        if (property_exists($user, 'email')) {
            return (string) $user->email;
        }
        return null;
    }
}
