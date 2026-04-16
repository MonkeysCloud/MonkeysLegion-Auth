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

namespace MonkeysLegion\Auth\Service;

use MonkeysLegion\Auth\DTO\PasswordPolicy;

/**
 * Password hashing service with configurable policy.
 *
 * SECURITY: Default algorithm is PASSWORD_ARGON2ID (most secure).
 * Falls back to PASSWORD_BCRYPT if argon2 is not available.
 *
 * PERFORMANCE: Cost/memory/threads tunable per deployment.
 */
final class PasswordHasher
{
    private string|int $algorithm;

    /** @var array<string, int|string> */
    private array $options;

    public function __construct(
        string|int|null $algorithm = null,
        private readonly PasswordPolicy $policy = new PasswordPolicy(),
        int $bcryptCost = 12,
        int $argonMemory = 65536,
        int $argonTime = 4,
        int $argonThreads = 1,
    ) {
        // Auto-detect best algorithm
        if ($algorithm !== null) {
            $this->algorithm = $algorithm;
        } elseif (defined('PASSWORD_ARGON2ID')) {
            $this->algorithm = PASSWORD_ARGON2ID;
        } else {
            $this->algorithm = PASSWORD_BCRYPT;
        }

        $this->options = match ($this->algorithm) {
            PASSWORD_BCRYPT => ['cost' => $bcryptCost],
            PASSWORD_ARGON2ID, PASSWORD_ARGON2I => [
                'memory_cost' => $argonMemory,
                'time_cost'   => $argonTime,
                'threads'     => $argonThreads,
            ],
            default => [],
        };
    }

    /**
     * Hash a password.
     *
     * SECURITY: Validates against policy before hashing.
     *
     * @throws \InvalidArgumentException If password fails policy validation.
     */
    public function hash(string $password): string
    {
        $errors = $this->policy->validate($password);
        if ($errors !== []) {
            throw new \InvalidArgumentException(implode(' ', $errors));
        }

        return $this->performHash($password);
    }

    /**
     * Hash without policy validation (for transparent rehash on login).
     *
     * SECURITY: Only use when the password was already verified.
     */
    public function hashWithoutPolicy(string $password): string
    {
        return $this->performHash($password);
    }

    /**
     * Verify a password against a hash.
     */
    public function verify(string $password, string $hash): bool
    {
        return password_verify($password, $hash);
    }

    /**
     * Check if a hash needs rehashing (algorithm/cost upgrade).
     */
    public function needsRehash(string $hash): bool
    {
        return password_needs_rehash($hash, $this->algorithm, $this->options);
    }

    /**
     * Get the current password policy.
     */
    public function getPolicy(): PasswordPolicy
    {
        return $this->policy;
    }

    /**
     * Validate a password against the policy (without hashing).
     *
     * @return list<string> Validation errors.
     */
    public function validatePolicy(string $password): array
    {
        return $this->policy->validate($password);
    }

    // ── Private ────────────────────────────────────────────────

    private function performHash(string $password): string
    {
        $hash = password_hash($password, $this->algorithm, $this->options);

        if ($hash === false) {
            throw new \RuntimeException('Password hashing failed.');
        }

        return $hash;
    }
}
