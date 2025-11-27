<?php

declare(strict_types=1);

namespace MonkeysLegion\Auth\Trait;

/**
 * Trait for implementing HasPermissionsInterface.
 *
 * Requires a $permissions property (array or JSON-decoded array).
 */
trait HasPermissionsTrait
{
    /**
     * Get all permissions (direct + via roles).
     *
     * @return string[]
     */
    public function getPermissions(): array
    {
        return $this->getDirectPermissions();
    }

    /**
     * Get directly assigned permissions.
     *
     * @return string[]
     */
    public function getDirectPermissions(): array
    {
        $permissions = $this->permissions ?? [];

        if (is_string($permissions)) {
            $permissions = json_decode($permissions, true) ?? [];
        }

        return (array) $permissions;
    }

    /**
     * Check if user has a specific permission.
     */
    public function hasPermission(string $permission): bool
    {
        $permissions = $this->getPermissions();

        // Wildcard check
        if (in_array('*', $permissions, true)) {
            return true;
        }

        // Exact match
        if (in_array($permission, $permissions, true)) {
            return true;
        }

        // Prefix match (e.g., "posts.*" matches "posts.create")
        foreach ($permissions as $p) {
            if (str_ends_with($p, '.*')) {
                $prefix = substr($p, 0, -1);
                if (str_starts_with($permission, $prefix)) {
                    return true;
                }
            }
        }

        return false;
    }

    /**
     * Check if user has any of the given permissions.
     *
     * @param string[] $permissions
     */
    public function hasAnyPermission(array $permissions): bool
    {
        foreach ($permissions as $permission) {
            if ($this->hasPermission($permission)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Check if user has all of the given permissions.
     *
     * @param string[] $permissions
     */
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
