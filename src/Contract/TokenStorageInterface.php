<?php

declare(strict_types=1);

namespace MonkeysLegion\Auth\Contract;

/**
 * Contract for token blacklist/whitelist storage.
 *
 * SECURITY: Implementations should use TTL-based expiry to prevent
 * unbounded storage growth.
 */
interface TokenStorageInterface
{
    /**
     * Store token metadata.
     *
     * @param array<string, mixed> $data Metadata (user_id, ip, user_agent, etc.).
     * @param int $ttl Time to live in seconds.
     */
    public function store(string $tokenId, array $data, int $ttl): void;

    /**
     * Get stored token data.
     *
     * @return array<string, mixed>|null
     */
    public function get(string $tokenId): ?array;

    /**
     * Blacklist a token (revoked).
     */
    public function blacklist(string $tokenId, int $ttl): void;

    /**
     * Check if a token is blacklisted.
     */
    public function isBlacklisted(string $tokenId): bool;

    /**
     * Remove all tokens for a user.
     */
    public function removeAllForUser(int|string $userId): void;
}
