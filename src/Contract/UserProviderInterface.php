<?php

declare(strict_types=1);

namespace MonkeysLegion\Auth\Contract;

/**
 * Contract for retrieving authenticatable users from storage.
 */
interface UserProviderInterface
{
    public function findById(int|string $id): ?AuthenticatableInterface;

    public function findByEmail(string $email): ?AuthenticatableInterface;

    public function findByRememberToken(int|string $id, string $token): ?AuthenticatableInterface;

    public function findByApiKey(string $key): ?AuthenticatableInterface;

    /**
     * @param array<string, mixed> $attributes
     */
    public function create(array $attributes): AuthenticatableInterface;

    public function updatePassword(int|string $id, string $hashedPassword): void;

    public function incrementTokenVersion(int|string $id): void;

    public function updateRememberToken(int|string $id, string $token): void;
}
