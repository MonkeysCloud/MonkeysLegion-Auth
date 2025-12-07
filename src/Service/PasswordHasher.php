<?php

declare(strict_types=1);

namespace MonkeysLegion\Auth\Service;

/**
 * Password hashing service with configurable algorithm and rehashing support.
 */
final class PasswordHasher
{
    public function __construct(
        private string|int|null $algorithm = PASSWORD_DEFAULT,
        private array $options = [],
        ?int $cost = null,
    ) {
        if ($cost !== null) {
            $this->options['cost'] = $cost;
        }
    }

    /**
     * Hash a password.
     */
    public function hash(string $password): string
    {
        return password_hash($password, $this->algorithm, $this->options);
    }

    /**
     * Verify a password against a hash.
     */
    public function verify(string $password, string $hash): bool
    {
        return password_verify($password, $hash);
    }

    /**
     * Check if a hash needs to be rehashed (algorithm/options changed).
     */
    public function needsRehash(string $hash): bool
    {
        return password_needs_rehash($hash, $this->algorithm, $this->options);
    }

    /**
     * Get password hash info.
     */
    public function getInfo(string $hash): array
    {
        return password_get_info($hash);
    }
}
