<?php

declare(strict_types=1);

namespace MonkeysLegion\Auth\Contract;

/**
 * Contract for authorization policies.
 */
interface PolicyInterface
{
    /**
     * Handle before checks. Return true to allow, false to deny, null to defer.
     *
     * Use this for super-admin bypass or other global checks.
     */
    public function before(?object $user, string $ability, ?object $model = null): ?bool;
}
