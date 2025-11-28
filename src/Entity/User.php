<?php

declare(strict_types=1);

namespace MonkeysLegion\Auth\Entity;

use MonkeysLegion\Auth\Contract\AuthenticatableInterface;
use MonkeysLegion\Auth\Contract\HasPermissionsInterface;
use MonkeysLegion\Auth\Contract\HasRolesInterface;
use MonkeysLegion\Auth\Trait\AuthenticatableTrait;
use MonkeysLegion\Auth\Trait\HasPermissionsTrait;
use MonkeysLegion\Auth\Trait\HasRolesTrait;

/**
 * Example User entity demonstrating trait usage.
 *
 * This is a sample implementation - customize for your needs.
 */
class User implements AuthenticatableInterface, HasRolesInterface, HasPermissionsInterface
{
    use AuthenticatableTrait;
    use HasRolesTrait;
    use HasPermissionsTrait;

    public function __construct(
        public int $id = 0,
        public string $email = '',
        public string $password_hash = '',
        public int $token_version = 1,
        public array $roles = [],
        public array $permissions = [],
        public ?string $two_factor_secret = null,
        public ?array $recovery_codes = null,
        public bool $email_verified = false,
        public ?\DateTimeInterface $email_verified_at = null,
        public ?\DateTimeInterface $created_at = null,
        public ?\DateTimeInterface $updated_at = null,
    ) {}

    /**
     * Check if 2FA is enabled.
     */
    public function hasTwoFactorEnabled(): bool
    {
        return $this->two_factor_secret !== null;
    }

    /**
     * Get the 2FA secret.
     */
    public function getTwoFactorSecret(): ?string
    {
        return $this->two_factor_secret;
    }

    /**
     * Check if email is verified.
     */
    public function hasVerifiedEmail(): bool
    {
        return $this->email_verified;
    }

    /**
     * Get recovery codes.
     */
    public function getRecoveryCodes(): array
    {
        return $this->recovery_codes ?? [];
    }
}
