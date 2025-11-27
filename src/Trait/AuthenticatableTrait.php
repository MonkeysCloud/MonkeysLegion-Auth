<?php

declare(strict_types=1);

namespace MonkeysLegion\Auth\Trait;

/**
 * Trait for implementing AuthenticatableInterface.
 *
 * Requires properties: $id, $password_hash (or $passwordHash), $token_version (optional).
 */
trait AuthenticatableTrait
{
    /**
     * Get the unique identifier for the user.
     */
    public function getAuthIdentifier(): int|string
    {
        return $this->id ?? $this->uuid ?? 0;
    }

    /**
     * Get the identifier name.
     */
    public function getAuthIdentifierName(): string
    {
        return property_exists($this, 'uuid') ? 'uuid' : 'id';
    }

    /**
     * Get the password hash.
     */
    public function getAuthPassword(): string
    {
        return $this->password_hash ?? $this->passwordHash ?? '';
    }

    /**
     * Get the token version for invalidation.
     */
    public function getTokenVersion(): int
    {
        return $this->token_version ?? $this->tokenVersion ?? 1;
    }
}
