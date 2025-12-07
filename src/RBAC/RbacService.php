<?php

declare(strict_types=1);

namespace MonkeysLegion\Auth\RBAC;

use MonkeysLegion\Auth\Contract\AuthenticatableInterface;
use PDO;

/**
 * Role-Based Access Control service.
 * 
 * Required tables:
 * 
 * CREATE TABLE roles (
 *     id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
 *     name VARCHAR(100) NOT NULL UNIQUE,
 *     description VARCHAR(255),
 *     created_at INT UNSIGNED NOT NULL
 * );
 * 
 * CREATE TABLE permissions (
 *     id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
 *     name VARCHAR(100) NOT NULL UNIQUE,
 *     description VARCHAR(255),
 *     created_at INT UNSIGNED NOT NULL
 * );
 * 
 * CREATE TABLE role_permissions (
 *     role_id BIGINT UNSIGNED NOT NULL,
 *     permission_id BIGINT UNSIGNED NOT NULL,
 *     PRIMARY KEY (role_id, permission_id)
 * );
 * 
 * CREATE TABLE user_roles (
 *     user_id BIGINT UNSIGNED NOT NULL,
 *     role_id BIGINT UNSIGNED NOT NULL,
 *     PRIMARY KEY (user_id, role_id)
 * );
 * 
 * CREATE TABLE user_permissions (
 *     user_id BIGINT UNSIGNED NOT NULL,
 *     permission_id BIGINT UNSIGNED NOT NULL,
 *     PRIMARY KEY (user_id, permission_id)
 * );
 */
final class RbacService
{
    /** @var array<int, string[]> Cache of user permissions */
    private array $permissionCache = [];

    /** @var array<int, string[]> Cache of user roles */
    private array $roleCache = [];

    public function __construct(
        private readonly PDO $pdo
    ) {}

    /**
     * Check if user has a specific role.
     */
    public function hasRole(int|AuthenticatableInterface $user, string $role): bool
    {
        $roles = $this->getUserRoles($user);
        return in_array($role, $roles, true);
    }

    /**
     * Check if user has any of the specified roles.
     *
     * @param string[] $roles
     */
    public function hasAnyRole(int|AuthenticatableInterface $user, array $roles): bool
    {
        $userRoles = $this->getUserRoles($user);
        return !empty(array_intersect($roles, $userRoles));
    }

    /**
     * Check if user has all specified roles.
     *
     * @param string[] $roles
     */
    public function hasAllRoles(int|AuthenticatableInterface $user, array $roles): bool
    {
        $userRoles = $this->getUserRoles($user);
        return empty(array_diff($roles, $userRoles));
    }

    /**
     * Check if user has a specific permission.
     */
    public function hasPermission(int|AuthenticatableInterface $user, string $permission): bool
    {
        $permissions = $this->getUserPermissions($user);
        
        // Check exact match
        if (in_array($permission, $permissions, true)) {
            return true;
        }

        // Check wildcards (e.g., 'posts.*' grants 'posts.edit')
        foreach ($permissions as $p) {
            if (str_ends_with($p, '.*')) {
                $prefix = substr($p, 0, -1);
                if (str_starts_with($permission, $prefix)) {
                    return true;
                }
            }
        }

        // Check super admin
        return in_array('*', $permissions, true);
    }

    /**
     * Check if user has any of the specified permissions.
     *
     * @param string[] $permissions
     */
    public function hasAnyPermission(int|AuthenticatableInterface $user, array $permissions): bool
    {
        foreach ($permissions as $permission) {
            if ($this->hasPermission($user, $permission)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Check if user has all specified permissions.
     *
     * @param string[] $permissions
     */
    public function hasAllPermissions(int|AuthenticatableInterface $user, array $permissions): bool
    {
        foreach ($permissions as $permission) {
            if (!$this->hasPermission($user, $permission)) {
                return false;
            }
        }
        return true;
    }

    /**
     * Get all roles for a user.
     *
     * @return string[]
     */
    public function getUserRoles(int|AuthenticatableInterface $user): array
    {
        $userId = $user instanceof AuthenticatableInterface 
            ? (int) $user->getAuthIdentifier() 
            : $user;

        if (isset($this->roleCache[$userId])) {
            return $this->roleCache[$userId];
        }

        $stmt = $this->pdo->prepare(
            'SELECT r.name FROM roles r
             INNER JOIN user_roles ur ON r.id = ur.role_id
             WHERE ur.user_id = ?'
        );
        $stmt->execute([$userId]);

        $roles = $stmt->fetchAll(PDO::FETCH_COLUMN);
        $this->roleCache[$userId] = $roles;

        return $roles;
    }

    /**
     * Get all permissions for a user (includes role permissions).
     *
     * @return string[]
     */
    public function getUserPermissions(int|AuthenticatableInterface $user): array
    {
        $userId = $user instanceof AuthenticatableInterface 
            ? (int) $user->getAuthIdentifier() 
            : $user;

        if (isset($this->permissionCache[$userId])) {
            return $this->permissionCache[$userId];
        }

        // Get direct user permissions
        $stmt1 = $this->pdo->prepare(
            'SELECT p.name FROM permissions p
             INNER JOIN user_permissions up ON p.id = up.permission_id
             WHERE up.user_id = ?'
        );
        $stmt1->execute([$userId]);
        $directPerms = $stmt1->fetchAll(PDO::FETCH_COLUMN);

        // Get role-based permissions
        $stmt2 = $this->pdo->prepare(
            'SELECT DISTINCT p.name FROM permissions p
             INNER JOIN role_permissions rp ON p.id = rp.permission_id
             INNER JOIN user_roles ur ON rp.role_id = ur.role_id
             WHERE ur.user_id = ?'
        );
        $stmt2->execute([$userId]);
        $rolePerms = $stmt2->fetchAll(PDO::FETCH_COLUMN);

        $permissions = array_unique(array_merge($directPerms, $rolePerms));
        $this->permissionCache[$userId] = $permissions;

        return $permissions;
    }

    /**
     * Assign a role to a user.
     */
    public function assignRole(int $userId, string $roleName): void
    {
        $roleId = $this->getRoleId($roleName);
        
        $stmt = $this->pdo->prepare(
            'INSERT IGNORE INTO user_roles (user_id, role_id) VALUES (?, ?)'
        );
        $stmt->execute([$userId, $roleId]);

        unset($this->roleCache[$userId], $this->permissionCache[$userId]);
    }

    /**
     * Remove a role from a user.
     */
    public function removeRole(int $userId, string $roleName): void
    {
        $roleId = $this->getRoleId($roleName);

        $stmt = $this->pdo->prepare(
            'DELETE FROM user_roles WHERE user_id = ? AND role_id = ?'
        );
        $stmt->execute([$userId, $roleId]);

        unset($this->roleCache[$userId], $this->permissionCache[$userId]);
    }

    /**
     * Assign a permission directly to a user.
     */
    public function assignPermission(int $userId, string $permissionName): void
    {
        $permId = $this->getPermissionId($permissionName);

        $stmt = $this->pdo->prepare(
            'INSERT IGNORE INTO user_permissions (user_id, permission_id) VALUES (?, ?)'
        );
        $stmt->execute([$userId, $permId]);

        unset($this->permissionCache[$userId]);
    }

    /**
     * Remove a permission from a user.
     */
    public function removePermission(int $userId, string $permissionName): void
    {
        $permId = $this->getPermissionId($permissionName);

        $stmt = $this->pdo->prepare(
            'DELETE FROM user_permissions WHERE user_id = ? AND permission_id = ?'
        );
        $stmt->execute([$userId, $permId]);

        unset($this->permissionCache[$userId]);
    }

    /**
     * Create a new role.
     */
    public function createRole(string $name, ?string $description = null): int
    {
        $stmt = $this->pdo->prepare(
            'INSERT INTO roles (name, description, created_at) VALUES (?, ?, ?)'
        );
        $stmt->execute([$name, $description, time()]);
        return (int) $this->pdo->lastInsertId();
    }

    /**
     * Create a new permission.
     */
    public function createPermission(string $name, ?string $description = null): int
    {
        $stmt = $this->pdo->prepare(
            'INSERT INTO permissions (name, description, created_at) VALUES (?, ?, ?)'
        );
        $stmt->execute([$name, $description, time()]);
        return (int) $this->pdo->lastInsertId();
    }

    /**
     * Assign a permission to a role.
     */
    public function assignPermissionToRole(string $roleName, string $permissionName): void
    {
        $roleId = $this->getRoleId($roleName);
        $permId = $this->getPermissionId($permissionName);

        $stmt = $this->pdo->prepare(
            'INSERT IGNORE INTO role_permissions (role_id, permission_id) VALUES (?, ?)'
        );
        $stmt->execute([$roleId, $permId]);

        // Clear all caches as this affects many users
        $this->permissionCache = [];
    }

    /**
     * Clear permission cache for a user.
     */
    public function clearCache(?int $userId = null): void
    {
        if ($userId === null) {
            $this->permissionCache = [];
            $this->roleCache = [];
        } else {
            unset($this->permissionCache[$userId], $this->roleCache[$userId]);
        }
    }

    private function getRoleId(string $name): int
    {
        $stmt = $this->pdo->prepare('SELECT id FROM roles WHERE name = ?');
        $stmt->execute([$name]);
        $id = $stmt->fetchColumn();

        if ($id === false) {
            throw new \RuntimeException("Role '{$name}' not found");
        }

        return (int) $id;
    }

    private function getPermissionId(string $name): int
    {
        $stmt = $this->pdo->prepare('SELECT id FROM permissions WHERE name = ?');
        $stmt->execute([$name]);
        $id = $stmt->fetchColumn();

        if ($id === false) {
            throw new \RuntimeException("Permission '{$name}' not found");
        }

        return (int) $id;
    }
}
