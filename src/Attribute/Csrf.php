<?php
declare(strict_types=1);

namespace MonkeysLegion\Auth\Attribute;

use Attribute;

/**
 * MonKeysLegion Framework — Auth Package
 *
 * Marks a route as requiring (or exempt from) CSRF verification.
 *
 * Usage:
 *   // Explicitly require CSRF on a route:
 *   #[Csrf(true)]
 *
 *   // Exempt a specific route from CSRF (overrides global middleware):
 *   #[Csrf(false)]
 *
 * By default, the global CsrfMiddleware / VerifyCsrfToken handles CSRF
 * for all state-changing requests. This attribute allows route-level
 * overrides.
 *
 * @copyright 2026 MonkeysCloud Team
 * @license   MIT
 */
#[Attribute(Attribute::TARGET_METHOD | Attribute::TARGET_CLASS)]
final class Csrf
{
    public function __construct(
        public readonly bool $require = true,
    ) {}
}
