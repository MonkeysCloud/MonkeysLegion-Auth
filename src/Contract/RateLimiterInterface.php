<?php

declare(strict_types=1);

namespace MonkeysLegion\Auth\Contract;

/**
 * Contract for rate limiting implementations.
 */
interface RateLimiterInterface
{
    /**
     * Attempt to hit the rate limiter.
     *
     * @param string $key Unique identifier (e.g., IP, user ID, email)
     * @param int $maxAttempts Maximum attempts allowed
     * @param int $decaySeconds Time window in seconds
     * @return bool True if attempt is allowed, false if rate limited
     */
    public function attempt(string $key, int $maxAttempts, int $decaySeconds): bool;

    /**
     * Get remaining attempts for a key.
     */
    public function remaining(string $key, int $maxAttempts): int;

    /**
     * Get seconds until rate limit resets.
     */
    public function availableIn(string $key): int;

    /**
     * Clear rate limit for a key.
     */
    public function clear(string $key): void;

    /**
     * Increment the attempt counter.
     */
    public function hit(string $key, int $decaySeconds): int;
}
