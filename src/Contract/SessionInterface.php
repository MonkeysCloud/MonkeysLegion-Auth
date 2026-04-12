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
 * Session backend contract.
 *
 * Since there is no official PSR for sessions, this provides a
 * minimal interface compatible with any session implementation
 * (native PHP sessions, Redis, database-backed, etc.).
 *
 * Adapters can wrap Symfony's SessionInterface, Laravel's Session,
 * or PHP's native $_SESSION superglobal.
 */
interface SessionInterface
{
    /**
     * Get a value from the session.
     */
    public function get(string $key, mixed $default = null): mixed;

    /**
     * Store a value in the session.
     */
    public function put(string $key, mixed $value): void;

    /**
     * Remove a value from the session.
     */
    public function forget(string $key): void;

    /**
     * Check if the session contains a key.
     */
    public function has(string $key): bool;

    /**
     * Regenerate the session ID.
     *
     * SECURITY: Must be called after authentication to prevent session fixation.
     *
     * @param bool $destroy Whether to destroy the old session data.
     */
    public function regenerate(bool $destroy = false): bool;

    /**
     * Invalidate the entire session.
     */
    public function invalidate(): bool;

    /**
     * Get the session ID.
     */
    public function getId(): string;
}
