<?php

declare(strict_types=1);

namespace MonkeysLegion\Auth\Service;

use MonkeysLegion\Auth\Contract\TokenStorageInterface;
use Redis;

/**
 * Redis-based token storage for blacklisting/revocation.
 */
final class RedisTokenStorage implements TokenStorageInterface
{
    public function __construct(
        private Redis $redis,
        private string $prefix = 'token:',
        private string $userIndexPrefix = 'user_tokens:',
    ) {}

    public function store(string $tokenId, array $data, int $ttl): void
    {
        $key = $this->prefix . $tokenId;
        $this->redis->setex($key, $ttl, json_encode($data, JSON_THROW_ON_ERROR));

        // Index by user ID if present
        if (isset($data['user_id'])) {
            $userKey = $this->userIndexPrefix . $data['user_id'];
            $this->redis->sAdd($userKey, $tokenId);
            $this->redis->expire($userKey, $ttl);
        }
    }

    public function exists(string $tokenId): bool
    {
        return (bool) $this->redis->exists($this->prefix . $tokenId);
    }

    public function get(string $tokenId): ?array
    {
        $data = $this->redis->get($this->prefix . $tokenId);
        if ($data === false) {
            return null;
        }

        return json_decode($data, true, 512, JSON_THROW_ON_ERROR);
    }

    public function remove(string $tokenId): void
    {
        $data = $this->get($tokenId);
        $this->redis->del($this->prefix . $tokenId);

        // Remove from user index
        if ($data && isset($data['user_id'])) {
            $userKey = $this->userIndexPrefix . $data['user_id'];
            $this->redis->sRem($userKey, $tokenId);
        }
    }

    public function removeAllForUser(int|string $userId): void
    {
        $userKey = $this->userIndexPrefix . $userId;
        $tokenIds = $this->redis->sMembers($userKey);

        foreach ($tokenIds as $tokenId) {
            $this->redis->del($this->prefix . $tokenId);
        }

        $this->redis->del($userKey);
    }

    /**
     * Add token to blacklist (for revocation).
     */
    public function blacklist(string $tokenId, int $ttl): void
    {
        $this->store($tokenId, ['blacklisted' => true, 'at' => time()], $ttl);
    }

    /**
     * Check if token is blacklisted.
     */
    public function isBlacklisted(string $tokenId): bool
    {
        $data = $this->get($tokenId);
        return $data !== null && ($data['blacklisted'] ?? false);
    }
}
