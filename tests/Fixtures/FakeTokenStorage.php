<?php

declare(strict_types=1);

namespace MonkeysLegion\Auth\Tests\Fixtures;

use MonkeysLegion\Auth\Contract\TokenStorageInterface;

class FakeTokenStorage implements TokenStorageInterface
{
    /** @var array<string, array{data: mixed, expires_at: int}> */
    private array $tokens = [];

    /** @var array<string, int> */
    private array $blacklist = [];

    /** @var array<int, array<string>> */
    private array $userTokens = [];

    public function store(string $tokenId, array $data, int $ttl): void
    {
        $this->tokens[$tokenId] = [
            'data' => $data,
            'expires_at' => time() + $ttl,
        ];

        // Track user tokens
        if (is_array($data) && isset($data['user_id'])) {
            $this->userTokens[$data['user_id']][] = $tokenId;
        }
    }

    public function exists(string $tokenId): bool
    {
        if (!isset($this->tokens[$tokenId])) {
            return false;
        }

        if ($this->tokens[$tokenId]['expires_at'] < time()) {
            unset($this->tokens[$tokenId]);
            return false;
        }

        return true;
    }

    public function get(string $tokenId): ?array
    {
        if (!isset($this->tokens[$tokenId])) {
            return null;
        }

        if ($this->tokens[$tokenId]['expires_at'] < time()) {
            unset($this->tokens[$tokenId]);
            return null;
        }

        return $this->tokens[$tokenId]['data'];
    }

    public function remove(string $tokenId): void
    {
        unset($this->tokens[$tokenId]);
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

        if ($this->blacklist[$tokenId] < time()) {
            unset($this->blacklist[$tokenId]);
            return false;
        }

        return true;
    }

    public function removeAllForUser(int|string $userId): void
    {
        if (isset($this->userTokens[$userId])) {
            foreach ($this->userTokens[$userId] as $tokenId) {
                unset($this->tokens[$tokenId]);
            }
            unset($this->userTokens[$userId]);
        }
    }

    public function getStoredTokens(): array
    {
        return $this->tokens;
    }

    public function getBlacklist(): array
    {
        return $this->blacklist;
    }

    public function clear(): void
    {
        $this->tokens = [];
        $this->blacklist = [];
        $this->userTokens = [];
    }
}
