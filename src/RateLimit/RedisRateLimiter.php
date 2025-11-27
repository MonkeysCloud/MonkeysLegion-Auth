<?php

declare(strict_types=1);

namespace MonkeysLegion\Auth\RateLimit;

use MonkeysLegion\Auth\Contract\RateLimiterInterface;
use Redis;
use RedisException;

/**
 * Redis-backed rate limiter for distributed environments.
 */
final class RedisRateLimiter implements RateLimiterInterface
{
    private const PREFIX = 'rate_limit:';

    public function __construct(
        private readonly Redis $redis
    ) {}

    public function attempt(string $key, int $maxAttempts = 5, int $decaySeconds = 60): bool
    {
        if ($this->tooManyAttempts($key, $maxAttempts)) {
            return false;
        }

        $this->hit($key, $decaySeconds);
        return true;
    }

    public function remaining(string $key, int $maxAttempts = 5): int
    {
        $count = (int) $this->redis->get(self::PREFIX . $key);
        return max(0, $maxAttempts - $count);
    }

    public function retryAfter(string $key): int
    {
        $ttl = $this->redis->ttl(self::PREFIX . $key);
        return $ttl > 0 ? $ttl : 0;
    }

    public function clear(string $key): void
    {
        $this->redis->del(self::PREFIX . $key);
    }

    public function hit(string $key, int $decaySeconds = 60): int
    {
        $fullKey = self::PREFIX . $key;
        
        // Use Lua script for atomic increment + expiry
        $script = <<<'LUA'
            local current = redis.call('INCR', KEYS[1])
            if current == 1 then
                redis.call('EXPIRE', KEYS[1], ARGV[1])
            end
            return current
        LUA;

        try {
            return (int) $this->redis->eval($script, [$fullKey, $decaySeconds], 1);
        } catch (RedisException) {
            // Fallback to non-atomic operation
            $count = (int) $this->redis->incr($fullKey);
            if ($count === 1) {
                $this->redis->expire($fullKey, $decaySeconds);
            }
            return $count;
        }
    }

    public function tooManyAttempts(string $key, int $maxAttempts = 5): bool
    {
        return (int) $this->redis->get(self::PREFIX . $key) >= $maxAttempts;
    }
}
