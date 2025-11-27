<?php

declare(strict_types=1);

namespace MonkeysLegion\Auth\Attribute;

use Attribute;

/**
 * Mark a route/method as requiring authentication.
 *
 * Usage:
 *   #[Authenticated]
 *   #[Authenticated(guard: 'api')]
 */
#[Attribute(Attribute::TARGET_METHOD | Attribute::TARGET_CLASS)]
final class Authenticated
{
    public function __construct(
        public ?string $guard = null,
    ) {}
}
