<?php

declare(strict_types=1);

namespace MonkeysLegion\Auth\Contract;

/**
 * Contract for entities that can be authenticated.
 */
interface AuthenticatableInterface
{
    /**
     * Get the unique identifier for the user.
     */
    public function getAuthIdentifier(): int|string;

    /**
     * Get the identifier name (e.g., 'id', 'uuid').
     */
    public function getAuthIdentifierName(): string;

    /**
     * Get the password hash for authentication.
     */
    public function getAuthPassword(): string;

    /**
     * Get the token version for token invalidation.
     */
    public function getTokenVersion(): int;
}
