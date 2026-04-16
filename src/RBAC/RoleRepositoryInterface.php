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

/**
 * Contract for RBAC storage — implementations can be PDO, in-memory, etc.
 */
interface RoleRepositoryInterface
{
    /** @return list<string> */
    public function getUserRoles(int $userId): array;

    /** @return list<string> */
    public function getUserPermissions(int $userId): array;

    public function assignRole(int $userId, string $roleName): void;

    public function removeRole(int $userId, string $roleName): void;

    public function assignPermission(int $userId, string $permissionName): void;

    public function removePermission(int $userId, string $permissionName): void;

    public function createRole(string $name, ?string $description = null): int;

    public function createPermission(string $name, ?string $description = null): int;

    public function assignPermissionToRole(string $roleName, string $permissionName): void;

    public function roleExists(string $name): bool;

    /** @return list<array{name: string, description: ?string}> */
    public function getAllRoles(): array;
}
