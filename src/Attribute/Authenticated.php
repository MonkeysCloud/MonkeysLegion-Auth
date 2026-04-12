<?php

declare(strict_types=1);

namespace MonkeysLegion\Auth\Attribute;

use Attribute;

/**
 * Require authentication — simple auth-required marker.
 *
 * Usage:
 *   #[Authenticated]              — any guard
 *   #[Authenticated(guard: 'api')] — specific guard
 */
#[Attribute(Attribute::TARGET_CLASS | Attribute::TARGET_METHOD)]
final readonly class Authenticated
{
    public function __construct(
        public ?string $guard = null,
    ) {}
}
