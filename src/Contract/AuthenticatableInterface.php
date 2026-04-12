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

namespace MonkeysLegion\Auth\Contract;

/**
 * Contract for entities that can be authenticated.
 *
 * SECURITY: Implementations must never expose raw password hashes
 * through serialization or public APIs.
 */
interface AuthenticatableInterface
{
    /**
     * Get the unique identifier for the user.
     */
    public function getAuthIdentifier(): int|string;

    /**
     * Get the identifier column name (e.g., 'id', 'uuid').
     */
    public function getAuthIdentifierName(): string;

    /**
     * Get the hashed password for credential verification.
     *
     * SECURITY: Must return a bcrypt/argon2 hash, never plaintext.
     */
    public function getAuthPassword(): string;

    /**
     * Get the token version for global token invalidation.
     *
     * Incrementing this value invalidates ALL issued tokens.
     */
    public function getTokenVersion(): int;

    /**
     * Get the remember-me token (if any).
     */
    public function getRememberToken(): ?string;

    /**
     * Set the remember-me token.
     */
    public function setRememberToken(string $token): void;
}
