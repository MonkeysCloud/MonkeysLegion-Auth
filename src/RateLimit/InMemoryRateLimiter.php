<?php

declare(strict_types=1);

namespace MonkeysLegion\Auth\RateLimit;

use MonkeysLegion\Auth\Contract\RateLimiterInterface;

/**
 * In-memory rate limiter (for single-server/testing).
 * For production, use RedisRateLimiter.
 */
final class InMemoryRateLimiter implements RateLimiterInterface
{
    /** @var array<string, array{count: int, expires_at: int}> */
    private array $cache = [];

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
        $this->cleanup($key);
        $count = $this->cache[$key]['count'] ?? 0;
        return max(0, $maxAttempts - $count);
    }

    public function retryAfter(string $key): int
    {
        if (!isset($this->cache[$key])) {
            return 0;
        }

        $expiresAt = $this->cache[$key]['expires_at'];
        return max(0, $expiresAt - time());
    }

    public function availableIn(string $key): int
    {
        return $this->retryAfter($key);
    }

    public function clear(string $key): void
    {
        unset($this->cache[$key]);
    }

    public function hit(string $key, int $decaySeconds = 60): int
    {
        $this->cleanup($key);
        $now = time();

        if (!isset($this->cache[$key])) {
            $this->cache[$key] = [
                'count' => 0,
                'expires_at' => $now + $decaySeconds,
            ];
        }

        $this->cache[$key]['count']++;
        return $this->cache[$key]['count'];
    }

    public function tooManyAttempts(string $key, int $maxAttempts = 5): bool
    {
        $this->cleanup($key);
        return ($this->cache[$key]['count'] ?? 0) >= $maxAttempts;
    }

    private function cleanup(string $key): void
    {
        if (isset($this->cache[$key]) && $this->cache[$key]['expires_at'] <= time()) {
            unset($this->cache[$key]);
        }
    }
}
