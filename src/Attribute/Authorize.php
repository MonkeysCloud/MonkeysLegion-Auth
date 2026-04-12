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
 * Policy-based authorization check.
 *
 * Usage:
 *   #[Authorize(ability: 'update', model: Post::class)]
 *   #[Authorize(ability: 'admin-panel')]
 */
#[Attribute(Attribute::TARGET_METHOD | Attribute::IS_REPEATABLE)]
final readonly class Authorize
{
    public function __construct(
        public string $ability,
        public ?string $model = null,
    ) {}
}
