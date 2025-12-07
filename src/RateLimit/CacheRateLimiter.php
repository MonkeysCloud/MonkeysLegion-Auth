<?php

declare(strict_types=1);

namespace MonkeysLegion\Auth\RateLimit;

use MonkeysLegion\Auth\Contract\RateLimiterInterface;
use Psr\SimpleCache\CacheInterface;

/**
 * PSR-16 cache-based rate limiter.
 * Works with any PSR-16 cache implementation.
 */
final class CacheRateLimiter implements RateLimiterInterface
{
    public function __construct(
        private CacheInterface $cache,
        private string $prefix = 'rate_limit:',
    ) {}

    public function attempt(string $key, int $maxAttempts, int $decaySeconds): bool
    {
        $current = $this->hit($key, $decaySeconds);
        return $current <= $maxAttempts;
    }

    public function hit(string $key, int $decaySeconds): int
    {
        $fullKey = $this->prefix . $key;
        $data = $this->cache->get($fullKey, ['hits' => [], 'expires' => 0]);

        $now = time();
        $windowStart = $now - $decaySeconds;

        // Filter out expired hits
        $hits = array_filter(
            $data['hits'] ?? [],
            fn(int $timestamp) => $timestamp > $windowStart
        );

        // Add current hit
        $hits[] = $now;

        // Store updated data
        $this->cache->set($fullKey, [
            'hits' => array_values($hits),
            'expires' => $now + $decaySeconds,
        ], $decaySeconds);

        return count($hits);
    }

    public function remaining(string $key, int $maxAttempts): int
    {
        $fullKey = $this->prefix . $key;
        $data = $this->cache->get($fullKey, ['hits' => []]);
        $count = count($data['hits'] ?? []);
        return max(0, $maxAttempts - $count);
    }

    public function availableIn(string $key): int
    {
        $fullKey = $this->prefix . $key;
        $data = $this->cache->get($fullKey);

        if (!$data || empty($data['hits'])) {
            return 0;
        }

        $oldestHit = min($data['hits']);
        return max(0, $oldestHit + ($data['expires'] - time()) - time());
    }

    public function clear(string $key): void
    {
        $this->cache->delete($this->prefix . $key);
    }
}
