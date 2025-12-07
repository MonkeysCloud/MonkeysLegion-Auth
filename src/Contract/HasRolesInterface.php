<?php

declare(strict_types=1);

namespace MonkeysLegion\Auth\Contract;

/**
 * Contract for entities that have roles.
 */
interface HasRolesInterface
{
    /**
     * Get all roles assigned to this entity.
     *
     * @return string[]
     */
    public function getRoles(): array;

    /**
     * Check if entity has a specific role.
     */
    public function hasRole(string $role): bool;

    /**
     * Check if entity has any of the given roles.
     *
     * @param string[] $roles
     */
    public function hasAnyRole(array $roles): bool;

    /**
     * Check if entity has all of the given roles.
     *
     * @param string[] $roles
     */
    public function hasAllRoles(array $roles): bool;
}
