<?php

declare(strict_types=1);

/**
 * MonkeysLegion Auth v2
 *
 * @package   MonkeysLegion\Auth
 * @author    MonkeysCloud <jorge@monkeys.cloud>
 * @license   MIT
 *
 * @requires  PHP 8.4
 */

namespace MonkeysLegion\Auth\Contract;

/**
 * Contract for rate limiting attempts.
 */
interface RateLimiterInterface
{
    /**
     * Record an attempt and check if the limit is exceeded.
     *
     * @return bool True if the attempt is allowed, false if rate limited.
     */
    public function attempt(string $key, int $maxAttempts, int $decaySeconds): bool;

    /**
     * Record a single hit.
     */
    public function hit(string $key, int $decaySeconds): int;

    /**
     * Get remaining attempts.
     */
    public function remaining(string $key, int $maxAttempts): int;

    /**
     * Get seconds until the rate limit resets.
     */
    public function availableIn(string $key): int;

    /**
     * Clear all attempts for a key.
     */
    public function clear(string $key): void;
}
