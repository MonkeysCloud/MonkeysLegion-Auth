<?php

declare(strict_types=1);

namespace MonkeysLegion\Auth\Trait;

/**
 * Default implementation of AuthenticatableInterface.
 *
 * Provides sensible defaults for entities that need authentication.
 */
trait AuthenticatableTrait
{
    protected int $tokenVersion = 0;
    protected ?string $rememberToken = null;

    public function getAuthIdentifier(): int|string
    {
        return $this->id;
    }

    public function getAuthIdentifierName(): string
    {
        return 'id';
    }

    public function getAuthPassword(): string
    {
        return $this->passwordHash ?? $this->password_hash ?? '';
    }

    public function getTokenVersion(): int
    {
        return $this->tokenVersion;
    }

    public function getRememberToken(): ?string
    {
        return $this->rememberToken;
    }

    public function setRememberToken(string $token): void
    {
        $this->rememberToken = $token;
    }
}
