<?php

declare(strict_types=1);

/**
 * MonkeysLegion Auth v2
 *
 * @package   MonkeysLegion\Auth
 * @author    MonkeysCloud <jorge@monkeyscloud.com>
 * @license   MIT
 *
 * @requires  PHP 8.4
 */

namespace MonkeysLegion\Auth\Contract;

/**
 * Contract for entities that have roles.
 */
interface HasRolesInterface
{
    /** @return list<string> */
    public function getRoles(): array;

    public function hasRole(string $role): bool;

    /** @param list<string> $roles */
    public function hasAnyRole(array $roles): bool;

    /** @param list<string> $roles */
    public function hasAllRoles(array $roles): bool;
}
