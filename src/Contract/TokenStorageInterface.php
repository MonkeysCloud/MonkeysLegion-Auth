<?php

declare(strict_types=1);

namespace MonkeysLegion\Auth\Contract;

/**
 * Contract for token storage (blacklist/whitelist).
 */
interface TokenStorageInterface
{
    /**
     * Store a token with optional metadata.
     */
    public function store(string $tokenId, array $data, int $ttl): void;

    /**
     * Check if a token exists in storage.
     */
    public function exists(string $tokenId): bool;

    /**
     * Get token data from storage.
     */
    public function get(string $tokenId): ?array;

    /**
     * Remove a token from storage.
     */
    public function remove(string $tokenId): void;

    /**
     * Remove all tokens for a user.
     */
    public function removeAllForUser(int|string $userId): void;
}
