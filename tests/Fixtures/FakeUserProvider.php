<?php

declare(strict_types=1);

namespace MonkeysLegion\Auth\Tests\Fixtures;

use MonkeysLegion\Auth\Contract\AuthenticatableInterface;
use MonkeysLegion\Auth\Contract\UserProviderInterface;

class FakeUserProvider implements UserProviderInterface
{
    /** @var array<int|string, FakeUser> */
    private array $users = [];
    
    private int $nextId = 1;

    public function __construct()
    {
        // Add default test user
        $this->addUser(new FakeUser(
            id: 1,
            email: 'test@example.com',
            passwordHash: password_hash('password123', PASSWORD_DEFAULT),
        ));
    }

    public function addUser(FakeUser $user): void
    {
        $this->users[$user->id] = $user;
        if ($user->id >= $this->nextId) {
            $this->nextId = $user->id + 1;
        }
    }

    public function findById(int|string $id): ?AuthenticatableInterface
    {
        return $this->users[$id] ?? null;
    }

    public function findByEmail(string $email): ?AuthenticatableInterface
    {
        foreach ($this->users as $user) {
            if ($user->email === $email) {
                return $user;
            }
        }
        return null;
    }

    public function findByCredentials(array $credentials): ?AuthenticatableInterface
    {
        $email = $credentials['email'] ?? null;
        if ($email) {
            return $this->findByEmail($email);
        }
        return null;
    }

    public function create(array $attributes): AuthenticatableInterface
    {
        $user = new FakeUser(
            id: $this->nextId++,
            email: $attributes['email'] ?? 'user@example.com',
            passwordHash: $attributes['password_hash'] ?? password_hash('password', PASSWORD_DEFAULT),
        );
        $this->addUser($user);
        return $user;
    }

    public function incrementTokenVersion(int|string $userId): void
    {
        if (isset($this->users[$userId])) {
            $this->users[$userId]->tokenVersion++;
        }
    }

    public function updatePassword(int|string $userId, string $passwordHash): void
    {
        if (isset($this->users[$userId])) {
            $this->users[$userId]->passwordHash = $passwordHash;
        }
    }

    public function getUsers(): array
    {
        return $this->users;
    }

    public function clear(): void
    {
        $this->users = [];
        $this->nextId = 1;
    }
}
