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

namespace MonkeysLegion\Auth\Trait;

/**
 * Default implementation of HasRolesInterface.
 */
trait HasRolesTrait
{
    /** @var list<string> */
    protected array $roles = [];

    public function getRoles(): array
    {
        return $this->roles;
    }

    public function hasRole(string $role): bool
    {
        return in_array($role, $this->roles, true);
    }

    public function hasAnyRole(array $roles): bool
    {
        return array_intersect($roles, $this->roles) !== [];
    }

    public function hasAllRoles(array $roles): bool
    {
        return array_diff($roles, $this->roles) === [];
    }
}
