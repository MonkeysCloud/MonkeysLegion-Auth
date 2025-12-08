<?php

declare(strict_types=1);

namespace MonkeysLegion\Auth\Storage;

use MonkeysLegion\Auth\Contract\AuthenticatableInterface;
use MonkeysLegion\Auth\Contract\UserProviderInterface;
use RuntimeException;

/**
 * In-memory user provider for testing and development purposes.
 * Provides a simple, non-persistent storage for user data.
 */
class InMemoryUserProvider implements UserProviderInterface
{
    /** @var array<int|string, AuthenticatableInterface> */
    private array $users = [];

    /** @var array<string, int|string> Email to ID mapping */
    private array $emailMap = [];

    private int $nextId = 1;

    /**
     * Add a user to the in-memory storage.
     */
    public function addUser(AuthenticatableInterface $user): void
    {
        $id = $user->getAuthIdentifier();
        $this->users[$id] = $user;

        // Update email mapping if user has email method
        if (method_exists($user, 'getEmail') && is_callable([$user, 'getEmail'])) {
            $email = call_user_func([$user, 'getEmail']);
            if (is_string($email)) {
                $this->emailMap[$email] = $id;
            }
        }

        // Update next ID if the user ID is numeric and higher
        if (is_int($id) && $id >= $this->nextId) {
            $this->nextId = $id + 1;
        }
    }

    public function findById(int|string $id): ?AuthenticatableInterface
    {
        return $this->users[$id] ?? null;
    }

    public function findByEmail(string $email): ?AuthenticatableInterface
    {
        $userId = $this->emailMap[$email] ?? null;

        if ($userId === null) {
            return null;
        }

        return $this->users[$userId] ?? null;
    }

    public function findByCredentials(array $credentials): ?AuthenticatableInterface
    {
        // Try email first
        if (isset($credentials['email'])) {
            return $this->findByEmail($credentials['email']);
        }

        // Try ID
        if (isset($credentials['id'])) {
            return $this->findById($credentials['id']);
        }

        // Fallback: search all users for matching credentials
        foreach ($this->users as $user) {
            $match = true;
            foreach ($credentials as $key => $value) {
                $getter = 'get' . ucfirst($key);
                if (!method_exists($user, $getter) || $user->$getter() !== $value) {
                    $match = false;
                    break;
                }
            }
            if ($match) {
                return $user;
            }
        }

        return null;
    }

    public function incrementTokenVersion(int|string $userId): void
    {
        $user = $this->users[$userId] ?? null;

        if ($user === null) {
            throw new RuntimeException("User with ID {$userId} not found");
        }

        // If the user has a public tokenVersion property, increment it
        if (
            property_exists($user, 'tokenVersion') &&
            (new \ReflectionProperty($user, 'tokenVersion'))->isPublic()
        ) {
            $user->tokenVersion++;
        }
    }

    public function create(array $attributes): AuthenticatableInterface
    {
        // This is a simplified implementation that requires a class name or factory
        // In practice, you'd need to know what type of user to create
        throw new RuntimeException(
            'InMemoryUserProvider::create() requires a concrete user class. ' .
                'Use addUser() instead to add pre-instantiated users.'
        );
    }

    public function updatePassword(int|string $userId, string $passwordHash): void
    {
        $user = $this->users[$userId] ?? null;

        if ($user === null) {
            throw new RuntimeException("User with ID {$userId} not found");
        }

        // If the user has a public passwordHash property, update it
        if (
            property_exists($user, 'passwordHash') &&
            (new \ReflectionProperty($user, 'passwordHash'))->isPublic()
        ) {
            $user->passwordHash = $passwordHash;
        }
    }

    /**
     * Get all users (for testing purposes).
     * 
     * @return array<int|string, AuthenticatableInterface>
     */
    public function getAllUsers(): array
    {
        return $this->users;
    }

    /**
     * Clear all users from storage.
     */
    public function clear(): void
    {
        $this->users = [];
        $this->emailMap = [];
        $this->nextId = 1;
    }

    /**
     * Get the number of users in storage.
     */
    public function count(): int
    {
        return count($this->users);
    }

    /**
     * Remove a user from storage.
     */
    public function removeUser(int|string $userId): void
    {
        $user = $this->users[$userId] ?? null;

        if ($user !== null) {
            // Remove from email map
            if (method_exists($user, 'getEmail') && is_callable([$user, 'getEmail'])) {
                $email = call_user_func([$user, 'getEmail']);
                if (is_string($email)) {
                    unset($this->emailMap[$email]);
                }
            }

            // Remove from users
            unset($this->users[$userId]);
        }
    }
}
