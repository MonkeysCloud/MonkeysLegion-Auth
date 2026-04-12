<?php

declare(strict_types=1);

namespace MonkeysLegion\Auth\Attribute;

use Attribute;

/**
 * Require specific permission(s) for access.
 *
 * Usage:
 *   #[RequiresPermission('posts.create')]
 *   #[RequiresPermission(['posts.create', 'posts.edit'], mode: 'any')]
 */
#[Attribute(Attribute::TARGET_CLASS | Attribute::TARGET_METHOD)]
final readonly class RequiresPermission
{
    /** @var list<string> */
    public array $permissions;

    /**
     * @param string|list<string> $permissions
     * @param 'all'|'any' $mode
     */
    public function __construct(
        string|array $permissions,
        public string $mode = 'all',
    ) {
        $this->permissions = is_array($permissions) ? $permissions : [$permissions];
    }
}
