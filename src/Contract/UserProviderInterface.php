<?php

declare(strict_types=1);

namespace MonkeysLegion\Auth\Contract;

/**
 * Contract for user retrieval.
 */
interface UserProviderInterface
{
    /**
     * Find a user by their unique identifier.
     */
    public function findById(int|string $id): ?AuthenticatableInterface;

    /**
     * Find a user by email.
     */
    public function findByEmail(string $email): ?AuthenticatableInterface;

    /**
     * Find a user by custom credentials.
     *
     * @param array<string, mixed> $credentials
     */
    public function findByCredentials(array $credentials): ?AuthenticatableInterface;

    /**
     * Update the user's token version (for token invalidation).
     */
    public function incrementTokenVersion(int|string $userId): void;

    /**
     * Create a new user.
     *
     * @param array<string, mixed> $attributes
     * @throws \RuntimeException If creation fails
     */
    public function create(array $attributes): AuthenticatableInterface;

    /**
     * Update user's password hash.
     */
    public function updatePassword(int|string $userId, string $passwordHash): void;
}
