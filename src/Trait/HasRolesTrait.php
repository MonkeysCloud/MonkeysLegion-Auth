<?php

declare(strict_types=1);

namespace MonkeysLegion\Auth\Trait;

/**
 * Trait for implementing HasRolesInterface.
 *
 * Requires a $roles property (array or JSON-decoded array).
 */
trait HasRolesTrait
{
    /**
     * Get all roles.
     *
     * @return string[]
     */
    public function getRoles(): array
    {
        $roles = $this->roles ?? [];

        if (is_string($roles)) {
            $roles = json_decode($roles, true) ?? [];
        }

        return (array) $roles;
    }

    /**
     * Check if user has a specific role.
     */
    public function hasRole(string $role): bool
    {
        return in_array($role, $this->getRoles(), true);
    }

    /**
     * Check if user has any of the given roles.
     *
     * @param string[] $roles
     */
    public function hasAnyRole(array $roles): bool
    {
        return !empty(array_intersect($roles, $this->getRoles()));
    }

    /**
     * Check if user has all of the given roles.
     *
     * @param string[] $roles
     */
    public function hasAllRoles(array $roles): bool
    {
        return empty(array_diff($roles, $this->getRoles()));
    }
}
