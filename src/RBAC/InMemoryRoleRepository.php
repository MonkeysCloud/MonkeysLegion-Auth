<?php

declare(strict_types=1);

namespace MonkeysLegion\Auth\RBAC;

/**
 * In-memory RBAC storage — for testing and lightweight usage.
 */
final class InMemoryRoleRepository implements RoleRepositoryInterface
{
    /** @var array<string, array{name: string, description: ?string, id: int}> */
    private array $roles = [];

    /** @var array<string, array{name: string, description: ?string, id: int}> */
    private array $permissions = [];

    /** @var array<int, list<string>> User ID → role names */
    private array $userRoles = [];

    /** @var array<int, list<string>> User ID → permission names */
    private array $userPermissions = [];

    /** @var array<string, list<string>> Role name → permission names */
    private array $rolePermissions = [];

    private int $nextId = 1;

    public function getUserRoles(int $userId): array
    {
        return $this->userRoles[$userId] ?? [];
    }

    public function getUserPermissions(int $userId): array
    {
        $direct = $this->userPermissions[$userId] ?? [];

        // Merge role-based permissions
        $rolePerms = [];
        foreach ($this->userRoles[$userId] ?? [] as $roleName) {
            foreach ($this->rolePermissions[$roleName] ?? [] as $perm) {
                $rolePerms[] = $perm;
            }
        }

        return array_values(array_unique(array_merge($direct, $rolePerms)));
    }

    public function assignRole(int $userId, string $roleName): void
    {
        $roles = $this->userRoles[$userId] ?? [];
        if (!in_array($roleName, $roles, true)) {
            $this->userRoles[$userId][] = $roleName;
        }
    }

    public function removeRole(int $userId, string $roleName): void
    {
        $this->userRoles[$userId] = array_values(
            array_filter(
                $this->userRoles[$userId] ?? [],
                fn(string $r) => $r !== $roleName,
            ),
        );
    }

    public function assignPermission(int $userId, string $permissionName): void
    {
        $perms = $this->userPermissions[$userId] ?? [];
        if (!in_array($permissionName, $perms, true)) {
            $this->userPermissions[$userId][] = $permissionName;
        }
    }

    public function removePermission(int $userId, string $permissionName): void
    {
        $this->userPermissions[$userId] = array_values(
            array_filter(
                $this->userPermissions[$userId] ?? [],
                fn(string $p) => $p !== $permissionName,
            ),
        );
    }

    public function createRole(string $name, ?string $description = null): int
    {
        $id = $this->nextId++;
        $this->roles[$name] = ['name' => $name, 'description' => $description, 'id' => $id];
        return $id;
    }

    public function createPermission(string $name, ?string $description = null): int
    {
        $id = $this->nextId++;
        $this->permissions[$name] = ['name' => $name, 'description' => $description, 'id' => $id];
        return $id;
    }

    public function assignPermissionToRole(string $roleName, string $permissionName): void
    {
        $perms = $this->rolePermissions[$roleName] ?? [];
        if (!in_array($permissionName, $perms, true)) {
            $this->rolePermissions[$roleName][] = $permissionName;
        }
    }

    public function roleExists(string $name): bool
    {
        return isset($this->roles[$name]);
    }

    public function getAllRoles(): array
    {
        return array_map(
            fn(array $r) => ['name' => $r['name'], 'description' => $r['description']],
            array_values($this->roles),
        );
    }
}
