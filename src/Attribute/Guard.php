<?php

declare(strict_types=1);

namespace MonkeysLegion\Auth\Attribute;

use Attribute;

/**
 * Declare which guard protects a route or controller.
 *
 * Usage:
 *   #[Guard('api')]       — JWT guard
 *   #[Guard('session')]   — Session-based guard
 *   #[Guard('api-key')]   — API key guard
 */
#[Attribute(Attribute::TARGET_CLASS | Attribute::TARGET_METHOD)]
final readonly class Guard
{
    public function __construct(
        public string $name = 'jwt',
    ) {}
}
