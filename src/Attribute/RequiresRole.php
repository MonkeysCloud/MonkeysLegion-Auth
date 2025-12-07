<?php

declare(strict_types=1);

namespace MonkeysLegion\Auth\Attribute;

use Attribute;

/**
 * Require specific role(s) for a route/method.
 *
 * Usage:
 *   #[RequiresRole('admin')]
 *   #[RequiresRole(['admin', 'moderator'], anyOf: true)]
 */
#[Attribute(Attribute::TARGET_METHOD | Attribute::TARGET_CLASS | Attribute::IS_REPEATABLE)]
final class RequiresRole
{
    /** @var string[] */
    public array $roles;

    /**
     * @param string|string[] $roles
     * @param bool $anyOf If true, user needs any of the roles. If false, user needs all roles.
     */
    public function __construct(
        string|array $roles,
        public bool $anyOf = true,
    ) {
        $this->roles = (array) $roles;
    }
}
