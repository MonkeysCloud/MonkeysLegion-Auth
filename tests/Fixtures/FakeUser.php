<?php

declare(strict_types=1);

namespace MonkeysLegion\Auth\Tests\Fixtures;

use MonkeysLegion\Auth\Contract\AuthenticatableInterface;
use MonkeysLegion\Auth\Contract\HasPermissionsInterface;
use MonkeysLegion\Auth\Contract\HasRolesInterface;
use MonkeysLegion\Auth\Contract\TwoFactorAuthenticatable;
use MonkeysLegion\Auth\Trait\AuthenticatableTrait;
use MonkeysLegion\Auth\Trait\HasPermissionsTrait;
use MonkeysLegion\Auth\Trait\HasRolesTrait;

/**
 * Test user entity.
 */
class FakeUser implements AuthenticatableInterface, HasRolesInterface, HasPermissionsInterface
{
    use AuthenticatableTrait;
    use HasRolesTrait;
    use HasPermissionsTrait;

    public function __construct(
        public readonly int $id,
        public readonly string $email,
        public string $passwordHash,
        int $tokenVersion = 0,
        array $roles = [],
        array $permissions = [],
    ) {
        $this->tokenVersion = $tokenVersion;
        $this->roles        = $roles;
        $this->permissions  = $permissions;
    }
}

class FakeUser2FA extends FakeUser implements TwoFactorAuthenticatable
{
    private bool $twoFactorEnabled = false;
    private ?string $twoFactorSecret = null;
    /** @var list<string> */
    private array $recoveryCodes = [];

    public function __construct(
        int $id,
        string $email,
        string $passwordHash,
        int $tokenVersion = 0,
        bool $twoFactorEnabled = false,
        ?string $twoFactorSecret = null,
        array $recoveryCodes = [],
    ) {
        parent::__construct($id, $email, $passwordHash, $tokenVersion);
        $this->twoFactorEnabled = $twoFactorEnabled;
        $this->twoFactorSecret  = $twoFactorSecret;
        $this->recoveryCodes    = $recoveryCodes;
    }

    public function hasTwoFactorEnabled(): bool
    {
        return $this->twoFactorEnabled;
    }

    public function getTwoFactorSecret(): ?string
    {
        return $this->twoFactorSecret;
    }

    public function getRecoveryCodes(): array
    {
        return $this->recoveryCodes;
    }

    public function setRecoveryCodes(array $codes): void
    {
        $this->recoveryCodes = $codes;
    }
}
