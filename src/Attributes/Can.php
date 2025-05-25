<?php

declare(strict_types=1);

namespace MonkeysLegion\Auth\Attributes;

use Attribute;

/**
 * #[Can('edit', Post::class)]
 * Guard a route or method by ability and optional model class.
 */
#[Attribute(Attribute::TARGET_METHOD | Attribute::TARGET_CLASS)]
final class Can
{
    public function __construct(
        public string $ability,
        public ?string $model = null
    ) {}
}