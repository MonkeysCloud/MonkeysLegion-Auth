<?php

declare(strict_types=1);

namespace MonkeysLegion\Auth\RBAC;

use MonkeysLegion\Auth\Contract\HasPermissionsInterface;
use MonkeysLegion\Auth\Contract\HasRolesInterface;

/**
 * Service for checking permissions.
 */
final class PermissionChecker
{
    public function __construct(
        private RoleRegistry $roles,
    ) {}

    /**
     * Check if user has a permission.
     */
    public function can(object $user, string $permission): bool
    {
        // Check direct permissions if implemented
        if ($user instanceof HasPermissionsInterface) {
            if ($user->hasPermission($permission)) {
                return true;
            }
        }

        // Check role-based permissions
        if ($user instanceof HasRolesInterface) {
            foreach ($user->getRoles() as $roleName) {
                $permissions = $this->roles->getPermissions($roleName);

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
            }
        }

        return false;
    }

    /**
     * Check if user has any of the given permissions.
     *
     * @param string[] $permissions
     */
    public function canAny(object $user, array $permissions): bool
    {
        foreach ($permissions as $permission) {
            if ($this->can($user, $permission)) {
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
    public function canAll(object $user, array $permissions): bool
    {
        foreach ($permissions as $permission) {
            if (!$this->can($user, $permission)) {
                return false;
            }
        }

        return true;
    }

    /**
     * Get all permissions a user has.
     *
     * @return string[]
     */
    public function getAllPermissions(object $user): array
    {
        $permissions = [];

        // Direct permissions
        if ($user instanceof HasPermissionsInterface) {
            $permissions = array_merge($permissions, $user->getPermissions());
        }

        // Role-based permissions
        if ($user instanceof HasRolesInterface) {
            foreach ($user->getRoles() as $roleName) {
                $rolePermissions = $this->roles->getPermissions($roleName);
                $permissions = array_merge($permissions, $rolePermissions);
            }
        }

        return array_values(array_unique($permissions));
    }

    /**
     * Check if user has a specific role.
     */
    public function hasRole(object $user, string $role): bool
    {
        if (!$user instanceof HasRolesInterface) {
            return false;
        }

        return in_array($role, $user->getRoles(), true);
    }

    /**
     * Check if user has any of the given roles.
     *
     * @param string[] $roles
     */
    public function hasAnyRole(object $user, array $roles): bool
    {
        if (!$user instanceof HasRolesInterface) {
            return false;
        }

        foreach ($roles as $role) {
            if ($this->hasRole($user, $role)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Check if user has all of the given roles.
     *
     * @param string[] $roles
     */
    public function hasAllRoles(object $user, array $roles): bool
    {
        if (!$user instanceof HasRolesInterface) {
            return false;
        }

        foreach ($roles as $role) {
            if (!$this->hasRole($user, $role)) {
                return false;
            }
        }

        return true;
    }
}
