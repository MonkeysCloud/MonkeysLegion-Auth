<?php

declare(strict_types=1);

/**
 * MonkeysLegion Auth v2
 *
 * @package   MonkeysLegion\Auth
 * @author    MonkeysCloud <jorge@monkeyscloud.com>
 * @license   MIT
 *
 * @requires  PHP 8.4
 */

namespace MonkeysLegion\Auth\Attribute;

use Attribute;

/**
 * Apply rate limiting to a route or controller.
 *
 * Usage:
 *   #[RateLimit(maxAttempts: 60, decaySeconds: 60)]
 *   #[RateLimit(maxAttempts: 5, decaySeconds: 900, key: 'login')]
 */
#[Attribute(Attribute::TARGET_CLASS | Attribute::TARGET_METHOD)]
final readonly class RateLimit
{
    public function __construct(
        public int $maxAttempts = 60,
        public int $decaySeconds = 60,
        public ?string $key = null,
    ) {}
}
