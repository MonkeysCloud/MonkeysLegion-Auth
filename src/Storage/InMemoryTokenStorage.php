<?php

declare(strict_types=1);

namespace MonkeysLegion\Auth\Storage;

use MonkeysLegion\Auth\Contract\TokenStorageInterface;

/**
 * In-memory token storage — for testing.
 *
 * SECURITY: Not suitable for production (no persistence across processes).
 */
final class InMemoryTokenStorage implements TokenStorageInterface
{
    /** @var array<string, array{data: array<string, mixed>, expires_at: int}> */
    private array $tokens = [];

    /** @var array<string, int> Token ID → blacklist expiry */
    private array $blacklist = [];

    public function store(string $tokenId, array $data, int $ttl): void
    {
        $this->tokens[$tokenId] = [
            'data'       => $data,
            'expires_at' => time() + $ttl,
        ];
    }

    public function get(string $tokenId): ?array
    {
        if (!isset($this->tokens[$tokenId])) {
            return null;
        }

        if (time() >= $this->tokens[$tokenId]['expires_at']) {
            unset($this->tokens[$tokenId]);
            return null;
        }

        return $this->tokens[$tokenId]['data'];
    }

    public function blacklist(string $tokenId, int $ttl): void
    {
        $this->blacklist[$tokenId] = time() + $ttl;
    }

    public function isBlacklisted(string $tokenId): bool
    {
        if (!isset($this->blacklist[$tokenId])) {
            return false;
        }

        if (time() >= $this->blacklist[$tokenId]) {
            unset($this->blacklist[$tokenId]);
            return false;
        }

        return true;
    }

    public function removeAllForUser(int|string $userId): void
    {
        $this->tokens = array_filter(
            $this->tokens,
            fn(array $entry) => ($entry['data']['user_id'] ?? null) !== $userId,
        );
    }
}
