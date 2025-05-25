<?php

declare(strict_types=1);

namespace MonkeysLegion\Auth\Policy;

interface PolicyInterface
{
    /**
     * Handle before checks. Return true to allow, false to deny, null to defer.
     */
    public function before(?object $user, string $ability, object|null $model = null): ?bool;
}