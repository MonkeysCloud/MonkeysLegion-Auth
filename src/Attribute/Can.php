<?php

declare(strict_types=1);

namespace MonkeysLegion\Auth\Attribute;

use Attribute;

/**
 * Guard a route/method by ability and optional model.
 *
 * Usage:
 *   #[Can('edit', Post::class)]
 *   #[Can('admin')]
 */
#[Attribute(Attribute::TARGET_METHOD | Attribute::TARGET_CLASS | Attribute::IS_REPEATABLE)]
final class Can
{
    public function __construct(
        public string $ability,
        public ?string $model = null,
    ) {}
}
