<?php

declare(strict_types=1);

namespace MonkeysLegion\Auth\Attribute;

use Attribute;

/**
 * Require specific permission(s) for a route/method.
 *
 * Usage:
 *   #[RequiresPermission('posts.create')]
 *   #[RequiresPermission(['posts.create', 'posts.edit'], anyOf: true)]
 */
#[Attribute(Attribute::TARGET_METHOD | Attribute::TARGET_CLASS | Attribute::IS_REPEATABLE)]
final class RequiresPermission
{
    /** @var string[] */
    public array $permissions;

    /**
     * @param string|string[] $permissions
     * @param bool $anyOf If true, user needs any of the permissions. If false, user needs all.
     */
    public function __construct(
        string|array $permissions,
        public bool $anyOf = true,
    ) {
        $this->permissions = (array) $permissions;
    }
}
