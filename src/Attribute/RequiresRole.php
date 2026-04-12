<?php

declare(strict_types=1);

namespace MonkeysLegion\Auth\Attribute;

use Attribute;

/**
 * Require specific role(s) for access.
 *
 * Usage:
 *   #[RequiresRole('admin')]
 *   #[RequiresRole(['admin', 'editor'], mode: 'any')]
 */
#[Attribute(Attribute::TARGET_CLASS | Attribute::TARGET_METHOD)]
final readonly class RequiresRole
{
    /** @var list<string> */
    public array $roles;

    /**
     * @param string|list<string> $roles
     * @param 'all'|'any' $mode Whether ALL or ANY roles are required.
     */
    public function __construct(
        string|array $roles,
        public string $mode = 'any',
    ) {
        $this->roles = is_array($roles) ? $roles : [$roles];
    }
}
