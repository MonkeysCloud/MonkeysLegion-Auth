<?php

declare(strict_types=1);

namespace MonkeysLegion\Auth\Tests\Fixtures;

use MonkeysLegion\Auth\Contract\AuthenticatableInterface;
use MonkeysLegion\Auth\Contract\HasRolesInterface;
use MonkeysLegion\Auth\Contract\HasPermissionsInterface;

class FakeUser implements AuthenticatableInterface, HasRolesInterface, HasPermissionsInterface
{
    public function __construct(
        public int $id = 1,
        public string $email = 'test@example.com',
        public string $passwordHash = '',
        public int $tokenVersion = 1,
        public bool $emailVerified = true,
        public array $roles = [],
        public array $permissions = [],
        public ?string $twoFactorSecret = null,
        public array $recoveryCodes = [],
    ) {
        if ($this->passwordHash === '') {
            $this->passwordHash = password_hash('password123', PASSWORD_DEFAULT);
        }
    }

    public function getAuthIdentifier(): int|string
    {
        return $this->id;
    }

    public function getAuthPassword(): string
    {
        return $this->passwordHash;
    }

    public function getEmail(): string
    {
        return $this->email;
    }

    public function getTokenVersion(): int
    {
        return $this->tokenVersion;
    }

    public function isEmailVerified(): bool
    {
        return $this->emailVerified;
    }

    public function getRoles(): array
    {
        return $this->roles;
    }

    public function getPermissions(): array
    {
        return $this->permissions;
    }

    public function hasRole(string $role): bool
    {
        return in_array($role, $this->roles, true);
    }

    public function hasPermission(string $permission): bool
    {
        return in_array($permission, $this->permissions, true)
            || in_array('*', $this->permissions, true);
    }

    public function hasTwoFactorEnabled(): bool
    {
        return $this->twoFactorSecret !== null;
    }

    public function getTwoFactorSecret(): ?string
    {
        return $this->twoFactorSecret;
    }

    public function getRecoveryCodes(): array
    {
        return $this->recoveryCodes;
    }
    public function getAuthIdentifierName(): string
    {
        return 'id';
    }

    public function hasAnyRole(array $roles): bool
    {
        foreach ($roles as $role) {
            if ($this->hasRole($role)) {
                return true;
            }
        }
        return false;
    }

    public function hasAllRoles(array $roles): bool
    {
        foreach ($roles as $role) {
            if (!$this->hasRole($role)) {
                return false;
            }
        }
        return true;
    }

    public function getDirectPermissions(): array
    {
        return $this->permissions;
    }

    public function hasAnyPermission(array $permissions): bool
    {
        foreach ($permissions as $permission) {
            if ($this->hasPermission($permission)) {
                return true;
            }
        }
        return false;
    }

    public function hasAllPermissions(array $permissions): bool
    {
        foreach ($permissions as $permission) {
            if (!$this->hasPermission($permission)) {
                return false;
            }
        }
        return true;
    }
}
