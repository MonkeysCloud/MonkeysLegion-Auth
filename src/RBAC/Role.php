<?php

declare(strict_types=1);

namespace MonkeysLegion\Auth\RBAC;

/**
 * Role definition with permissions.
 */
final class Role
{
    /**
     * @param string[] $permissions
     * @param string[] $inherits Roles this role inherits from
     */
    public function __construct(
        public readonly string $name,
        public readonly array $permissions = [],
        public readonly array $inherits = [],
        public readonly ?string $description = null,
    ) {}

    public function hasPermission(string $permission): bool
    {
        return in_array($permission, $this->permissions, true)
            || in_array('*', $this->permissions, true);
    }
}
