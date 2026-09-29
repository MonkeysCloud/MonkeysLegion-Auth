<?php
declare(strict_types=1);

namespace MonkeysLegion\Auth\Security;

use Psr\SimpleCache\CacheInterface;

/**
 * MonKeysLegion Framework — Auth Package
 *
 * Checks passwords against the Have I Been Pwned (HIBP) database
 * using the k-anonymity model: only the first 5 characters of the
 * SHA-1 hash are sent to the API, protecting the plaintext password.
 *
 * Flow:
 *  1. SHA-1 hash the password
 *  2. Send first 5 hex chars to api.pwnedpasswords.com/range/{prefix}
 *  3. API returns all suffixes matching that prefix with breach counts
 *  4. Compare full hash suffix against returned list
 *
 * SECURITY: The full hash is never sent. The password is never sent.
 *
 * @copyright 2026 MonkeysCloud Team
 * @license   MIT
 */
final class PwnedPasswordChecker
{
    private const string API_URL = 'https://api.pwnedpasswords.com/range/';

    /**
     * @param CacheInterface|null $cache     PSR-16 cache for prefix results.
     * @param bool                $enabled   If false, always returns false (not pwned).
     * @param int                 $threshold Minimum breach count to consider "pwned".
     * @param int                 $cacheTtl  Cache TTL in seconds (default 24h).
     */
    public function __construct(
        private readonly ?CacheInterface $cache = null,
        private readonly bool $enabled = true,
        private readonly int $threshold = 1,
        private readonly int $cacheTtl = 86400,
    ) {}

    /**
     * Check if a password has been found in known data breaches.
     *
     * @param string $password The plaintext password to check.
     *
     * @return bool True if the password is compromised (pwned).
     */
    public function isPwned(string $password): bool
    {
        if (!$this->enabled) {
            return false;
        }

        $hash     = strtoupper(sha1($password));
        $prefix   = substr($hash, 0, 5);
        $suffix   = substr($hash, 5);
        $cacheKey = 'pwned:' . $prefix;

        $ranges = null;

        // Try cache first.
        if ($this->cache !== null) {
            $cached = $this->cache->get($cacheKey, null);
            if ($cached !== null && is_string($cached)) {
                $ranges = $cached;
            }
        }

        // Fetch from API on cache miss.
        if ($ranges === null) {
            $ranges = $this->fetchRange($prefix);
            if ($ranges === null) {
                // API failure — fail open (do not block users on infra issues).
                return false;
            }

            if ($this->cache !== null) {
                $this->cache->set($cacheKey, $ranges, $this->cacheTtl);
            }
        }

        return $this->findSuffix($ranges, $suffix);
    }

    /**
     * Fetch the range of hash suffixes from the HIBP API.
     *
     * @param string $prefix First 5 characters of SHA-1 hash.
     *
     * @return string|null Raw API response (suffixes with counts), or null on failure.
     */
    protected function fetchRange(string $prefix): ?string
    {
        $url = self::API_URL . $prefix;

        $context = stream_context_create([
            'http' => [
                'method'     => 'GET',
                'header'     => "User-Agent: MonKeysLegion-Security-Check\r\n",
                'timeout'    => 5,
                'ignore_errors' => true,
            ],
            'ssl' => [
                'verify_peer'    => true,
                'verify_peer_name' => true,
            ],
        ]);

        $response = @file_get_contents($url, false, $context);

        if ($response === false) {
            // API unreachable — fail open.
            return null;
        }

        return $response;
    }

    /**
     * Search the API response for the hash suffix and check breach count.
     *
     * @param string $ranges  Raw API response (format: "SUFFIX:COUNT\r\n...").
     * @param string $suffix  The suffix of the password hash to find.
     *
     * @return bool True if found and breach count >= threshold.
     */
    private function findSuffix(string $ranges, string $suffix): bool
    {
        $lines = explode("\n", $ranges);

        foreach ($lines as $line) {
            $line = trim($line);
            if ($line === '') {
                continue;
            }

            $parts = explode(':', $line, 2);
            if (count($parts) !== 2) {
                continue;
            }

            [$hashSuffix, $count] = $parts;
            $hashSuffix = strtoupper(trim($hashSuffix));
            $count      = (int) trim($count);

            if ($hashSuffix === $suffix && $count >= $this->threshold) {
                return true;
            }
        }

        return false;
    }

    /**
     * Check if the checker is enabled.
     */
    public function isEnabled(): bool
    {
        return $this->enabled;
    }
}
