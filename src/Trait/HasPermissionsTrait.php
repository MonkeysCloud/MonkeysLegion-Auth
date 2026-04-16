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
 * Default implementation of HasPermissionsInterface.
 */
trait HasPermissionsTrait
{
    /** @var list<string> */
    protected array $permissions = [];

    public function getPermissions(): array
    {
        return $this->permissions;
    }

    public function hasPermission(string $permission): bool
    {
        if (in_array($permission, $this->permissions, true)) {
            return true;
        }
        // Wildcard
        foreach ($this->permissions as $p) {
            if (str_ends_with($p, '.*')) {
                $prefix = substr($p, 0, -1);
                if (str_starts_with($permission, $prefix)) {
                    return true;
                }
            }
        }
        return in_array('*', $this->permissions, true);
    }

    public function hasAnyPermission(array $permissions): bool
    {
        foreach ($permissions as $p) {
            if ($this->hasPermission($p)) {
                return true;
            }
        }
        return false;
    }

    public function hasAllPermissions(array $permissions): bool
    {
        foreach ($permissions as $p) {
            if (!$this->hasPermission($p)) {
                return false;
            }
        }
        return true;
    }
}
