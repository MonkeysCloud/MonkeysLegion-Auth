<?php

declare(strict_types=1);

namespace MonkeysLegion\Auth\Policy;

use MonkeysLegion\Auth\Contract\HasRolesInterface;
use MonkeysLegion\Auth\Contract\PolicyInterface;

/**
 * Abstract base class for policies.
 *
 * Provides common functionality like admin bypass.
 */
abstract class AbstractPolicy implements PolicyInterface
{
    /**
     * Admin role names that bypass all checks.
     *
     * @var string[]
     */
    protected array $adminRoles = ['admin', 'super-admin', 'superadmin'];

    /**
     * Before hook - runs before any ability check.
     *
     * By default, allows admin users to do anything.
     * Override this to customize the before behavior.
     */
    public function before(?object $user, string $ability, ?object $model = null): ?bool
    {
        if ($user === null) {
            return false;
        }

        // Admin bypass
        if ($user instanceof HasRolesInterface) {
            if ($user->hasAnyRole($this->adminRoles)) {
                return true;
            }
        }

        return null; // Defer to specific ability method
    }

    /**
     * Check if user owns the model.
     * Override this to customize ownership check.
     */
    protected function isOwner(?object $user, object $model): bool
    {
        if ($user === null) {
            return false;
        }

        // Try various common patterns
        $userId = method_exists($user, 'getAuthIdentifier')
            ? $user->getAuthIdentifier()
            : ($user->id ?? null);

        if ($userId === null) {
            return false;
        }

        // Check user_id property
        if (property_exists($model, 'user_id')) {
            return $model->user_id === $userId;
        }

        // Check userId property
        if (property_exists($model, 'userId')) {
            return $model->userId === $userId;
        }

        // Check getUserId method
        if (method_exists($model, 'getUserId')) {
            return $model->getUserId() === $userId;
        }

        // Check author_id property
        if (property_exists($model, 'author_id')) {
            return $model->author_id === $userId;
        }

        // Check owner_id property
        if (property_exists($model, 'owner_id')) {
            return $model->owner_id === $userId;
        }

        return false;
    }
}
