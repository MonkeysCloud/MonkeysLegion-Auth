<?php

declare(strict_types=1);

namespace MonkeysLegion\Auth\RBAC;

/**
 * Registry for role definitions.
 */
final class RoleRegistry
{
    /** @var array<string, Role> */
    private array $roles = [];

    /**
     * Register a role.
     *
     * @param Role|string $role Role object or name
     * @param string[]|null $permissions Permissions if $role is a string
     */
    public function register(Role|string $role, ?array $permissions = null): self
    {
        if (is_string($role)) {
            $role = new Role($role, $permissions ?? []);
        }

        $this->roles[$role->name] = $role;
        return $this;
    }

    /**
     * Register multiple roles from config array.
     *
     * @param array<string, array{permissions?: string[], inherits?: string[], description?: string}> $config
     */
    public function registerFromConfig(array $config): self
    {
        foreach ($config as $name => $definition) {
            $this->register(new Role(
                name: $name,
                permissions: $definition['permissions'] ?? [],
                inherits: $definition['inherits'] ?? [],
                description: $definition['description'] ?? null,
            ));
        }

        return $this;
    }

    /**
     * Get a role by name.
     */
    public function get(string $name): ?Role
    {
        return $this->roles[$name] ?? null;
    }

    /**
     * Check if a role exists.
     */
    public function has(string $name): bool
    {
        return isset($this->roles[$name]);
    }

    /**
     * Get all permissions for a role (including inherited).
     *
     * @return string[]
     */
    public function getPermissions(string $roleName): array
    {
        return $this->resolvePermissions($roleName, []);
    }

    /**
     * Alias for getPermissions().
     *
     * @return string[]
     */
    public function getRolePermissions(string $roleName): array
    {
        return $this->getPermissions($roleName);
    }

    /**
     * Alias for has().
     */
    public function exists(string $name): bool
    {
        return $this->has($name);
    }

    /**
     * @param string[] $visited Prevent infinite recursion
     * @return string[]
     */
    private function resolvePermissions(string $roleName, array $visited): array
    {
        if (in_array($roleName, $visited, true)) {
            return []; // Circular inheritance protection
        }

        $role = $this->get($roleName);
        if (!$role) {
            return [];
        }

        $visited[] = $roleName;
        $permissions = $role->permissions;

        // Resolve inherited permissions
        foreach ($role->inherits as $parentRole) {
            $parentPermissions = $this->resolvePermissions($parentRole, $visited);
            $permissions = array_merge($permissions, $parentPermissions);
        }

        return array_values(array_unique($permissions));
    }

    /**
     * Get all registered roles.
     *
     * @return array<string, Role>
     */
    public function all(): array
    {
        return $this->roles;
    }
}
