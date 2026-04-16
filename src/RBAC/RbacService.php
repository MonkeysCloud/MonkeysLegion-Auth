<?php

declare(strict_types=1);

/**
 * MonkeysLegion Auth v2
 *
 * @package   MonkeysLegion\Auth
 * @author    MonkeysCloud <jorge@monkeys.cloud>
 * @license   MIT
 *
 * @requires  PHP 8.4
 */

namespace MonkeysLegion\Auth\RBAC;

use MonkeysLegion\Auth\Contract\AuthenticatableInterface;

/**
 * Role-Based Access Control service — decoupled from storage.
 *
 * PERFORMANCE: In-memory permission cache per user.
 * SECURITY: Wildcard permissions (e.g. 'posts.*') and super-admin ('*').
 */
final class RbacService
{
    /** @var array<int, list<string>> */
    private array $permissionCache = [];

    /** @var array<int, list<string>> */
    private array $roleCache = [];

    /**
     * @param RoleRepositoryInterface $repository Storage backend.
     */
    public function __construct(
        private readonly RoleRepositoryInterface $repository,
    ) {}

    // ── Role Checks ────────────────────────────────────────────

    public function hasRole(int|AuthenticatableInterface $user, string $role): bool
    {
        $roles = $this->getUserRoles($user);
        return in_array($role, $roles, true);
    }

    /** @param list<string> $roles */
    public function hasAnyRole(int|AuthenticatableInterface $user, array $roles): bool
    {
        $userRoles = $this->getUserRoles($user);
        return array_intersect($roles, $userRoles) !== [];
    }

    /** @param list<string> $roles */
    public function hasAllRoles(int|AuthenticatableInterface $user, array $roles): bool
    {
        $userRoles = $this->getUserRoles($user);
        return array_diff($roles, $userRoles) === [];
    }

    // ── Permission Checks ──────────────────────────────────────

    public function hasPermission(int|AuthenticatableInterface $user, string $permission): bool
    {
        $permissions = $this->getUserPermissions($user);

        // Exact match
        if (in_array($permission, $permissions, true)) {
            return true;
        }

        // Wildcard match (e.g. 'posts.*' grants 'posts.edit')
        foreach ($permissions as $p) {
            if (str_ends_with($p, '.*')) {
                $prefix = substr($p, 0, -1);
                if (str_starts_with($permission, $prefix)) {
                    return true;
                }
            }
        }

        // Super admin
        return in_array('*', $permissions, true);
    }

    /** @param list<string> $permissions */
    public function hasAnyPermission(int|AuthenticatableInterface $user, array $permissions): bool
    {
        foreach ($permissions as $permission) {
            if ($this->hasPermission($user, $permission)) {
                return true;
            }
        }
        return false;
    }

    /** @param list<string> $permissions */
    public function hasAllPermissions(int|AuthenticatableInterface $user, array $permissions): bool
    {
        foreach ($permissions as $permission) {
            if (!$this->hasPermission($user, $permission)) {
                return false;
            }
        }
        return true;
    }

    // ── Data Access ────────────────────────────────────────────

    /** @return list<string> */
    public function getUserRoles(int|AuthenticatableInterface $user): array
    {
        $userId = $this->resolveUserId($user);

        if (isset($this->roleCache[$userId])) {
            return $this->roleCache[$userId];
        }

        $roles = $this->repository->getUserRoles($userId);
        $this->roleCache[$userId] = $roles;

        return $roles;
    }

    /** @return list<string> */
    public function getUserPermissions(int|AuthenticatableInterface $user): array
    {
        $userId = $this->resolveUserId($user);

        if (isset($this->permissionCache[$userId])) {
            return $this->permissionCache[$userId];
        }

        $permissions = $this->repository->getUserPermissions($userId);
        $this->permissionCache[$userId] = $permissions;

        return $permissions;
    }

    // ── Management ─────────────────────────────────────────────

    public function assignRole(int $userId, string $roleName): void
    {
        $this->repository->assignRole($userId, $roleName);
        unset($this->roleCache[$userId], $this->permissionCache[$userId]);
    }

    public function removeRole(int $userId, string $roleName): void
    {
        $this->repository->removeRole($userId, $roleName);
        unset($this->roleCache[$userId], $this->permissionCache[$userId]);
    }

    public function assignPermission(int $userId, string $permissionName): void
    {
        $this->repository->assignPermission($userId, $permissionName);
        unset($this->permissionCache[$userId]);
    }

    public function removePermission(int $userId, string $permissionName): void
    {
        $this->repository->removePermission($userId, $permissionName);
        unset($this->permissionCache[$userId]);
    }

    public function clearCache(?int $userId = null): void
    {
        if ($userId === null) {
            $this->permissionCache = [];
            $this->roleCache       = [];
        } else {
            unset($this->permissionCache[$userId], $this->roleCache[$userId]);
        }
    }

    private function resolveUserId(int|AuthenticatableInterface $user): int
    {
        return $user instanceof AuthenticatableInterface
            ? (int) $user->getAuthIdentifier()
            : $user;
    }
}
