<?php

declare(strict_types=1);

namespace MonkeysLegion\Auth\ApiKey;

/**
 * Repository interface for API key storage.
 */
interface ApiKeyRepositoryInterface
{
    /**
     * Create a new API key record.
     *
     * @return int|string The key ID
     */
    public function create(array $data): int|string;

    /**
     * Find an API key by its prefix.
     */
    public function findByPrefix(string $prefix): ?array;

    /**
     * Find an API key by ID.
     */
    public function findById(int|string $id): ?array;

    /**
     * Find all API keys for a user.
     */
    public function findByUserId(int|string $userId): array;

    /**
     * Update the last used timestamp.
     */
    public function updateLastUsed(int|string $id): void;

    /**
     * Revoke an API key.
     */
    public function revoke(int|string $id): void;

    /**
     * Revoke all API keys for a user.
     */
    public function revokeAllForUser(int|string $userId): void;

    /**
     * Delete an API key.
     */
    public function delete(int|string $id): void;
}
