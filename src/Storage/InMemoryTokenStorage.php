<?php

declare(strict_types=1);

namespace MonkeysLegion\Auth\Storage;

use MonkeysLegion\Auth\Contract\TokenStorageInterface;

/**
 * In-memory token storage for short-lived persistence (per-request)
 * or for development where valid tokens are not tracked persistently.
 */
class InMemoryTokenStorage implements TokenStorageInterface
{
    private array $tokens = [];
    private array $blacklist = [];

    public function store(string $tokenId, array $data, int $ttl): void
    {
        $this->tokens[$tokenId] = [
            'data' => $data,
            'expires_at' => time() + $ttl,
            'user_id' => $data['id'] ?? null,
        ];
    }

    public function exists(string $tokenId): bool
    {
        if (!isset($this->tokens[$tokenId])) {
            return false;
        }

        if (time() > $this->tokens[$tokenId]['expires_at']) {
            unset($this->tokens[$tokenId]);
            return false;
        }

        return true;
    }

    public function get(string $tokenId): ?array
    {
        if (!$this->exists($tokenId)) {
            return null;
        }

        return $this->tokens[$tokenId]['data'];
    }

    public function remove(string $tokenId): void
    {
        unset($this->tokens[$tokenId]);
    }

    public function removeAllForUser(int|string $userId): void
    {
        foreach ($this->tokens as $tokenId => $data) {
            if (($data['user_id'] ?? null) === $userId) {
                unset($this->tokens[$tokenId]);
            }
        }
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

        if (time() > $this->blacklist[$tokenId]) {
            unset($this->blacklist[$tokenId]);
            return false;
        }

        return true;
    }
}
