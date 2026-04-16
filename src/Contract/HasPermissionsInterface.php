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

namespace MonkeysLegion\Auth\Contract;

/**
 * Contract for entities that have permissions.
 */
interface HasPermissionsInterface
{
    /** @return list<string> */
    public function getPermissions(): array;

    public function hasPermission(string $permission): bool;

    /** @param list<string> $permissions */
    public function hasAnyPermission(array $permissions): bool;

    /** @param list<string> $permissions */
    public function hasAllPermissions(array $permissions): bool;
}
