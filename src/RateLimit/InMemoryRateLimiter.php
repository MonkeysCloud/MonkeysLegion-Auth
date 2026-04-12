<?php

declare(strict_types=1);

/**
 * MonkeysLegion Auth v2
 *
 * @package   MonkeysLegion\Auth
 * @author    MonkeysCloud <jorge@monkeyscloud.com>
 * @license   MIT
 *
 * @requires  PHP 8.4
 */

namespace MonkeysLegion\Auth\RateLimit;

use MonkeysLegion\Auth\Contract\RateLimiterInterface;

/**
 * In-memory rate limiter — for testing and single-process apps.
 *
 * PERFORMANCE: Uses fixed-window counters with TTL.
 */
final class InMemoryRateLimiter implements RateLimiterInterface
{
    /** @var array<string, array{hits: int, expires_at: int}> */
    private array $attempts = [];

    public function attempt(string $key, int $maxAttempts, int $decaySeconds): bool
    {
        $this->cleanup($key);
        $current = $this->attempts[$key]['hits'] ?? 0;

        if ($current >= $maxAttempts) {
            return false;
        }

        $this->hit($key, $decaySeconds);
        return true;
    }

    public function hit(string $key, int $decaySeconds): int
    {
        $this->cleanup($key);

        if (!isset($this->attempts[$key])) {
            $this->attempts[$key] = [
                'hits'       => 0,
                'expires_at' => time() + $decaySeconds,
            ];
        }

        return ++$this->attempts[$key]['hits'];
    }

    public function remaining(string $key, int $maxAttempts): int
    {
        $this->cleanup($key);
        $current = $this->attempts[$key]['hits'] ?? 0;
        return max(0, $maxAttempts - $current);
    }

    public function availableIn(string $key): int
    {
        if (!isset($this->attempts[$key])) {
            return 0;
        }
        return max(0, $this->attempts[$key]['expires_at'] - time());
    }

    public function clear(string $key): void
    {
        unset($this->attempts[$key]);
    }

    private function cleanup(string $key): void
    {
        if (isset($this->attempts[$key]) && time() >= $this->attempts[$key]['expires_at']) {
            unset($this->attempts[$key]);
        }
    }
}
