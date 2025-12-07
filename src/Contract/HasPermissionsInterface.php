<?php

declare(strict_types=1);

namespace MonkeysLegion\Auth\Contract;

/**
 * Contract for entities that have permissions.
 */
interface HasPermissionsInterface
{
    /**
     * Get all permissions (direct + via roles).
     *
     * @return string[]
     */
    public function getPermissions(): array;

    /**
     * Get directly assigned permissions.
     *
     * @return string[]
     */
    public function getDirectPermissions(): array;

    /**
     * Check if entity has a specific permission.
     */
    public function hasPermission(string $permission): bool;

    /**
     * Check if entity has any of the given permissions.
     *
     * @param string[] $permissions
     */
    public function hasAnyPermission(array $permissions): bool;

    /**
     * Check if entity has all of the given permissions.
     *
     * @param string[] $permissions
     */
    public function hasAllPermissions(array $permissions): bool;
}
