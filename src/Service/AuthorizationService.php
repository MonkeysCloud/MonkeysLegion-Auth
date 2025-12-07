<?php

declare(strict_types=1);

namespace MonkeysLegion\Auth\Service;

use MonkeysLegion\Auth\Contract\HasRolesInterface;
use MonkeysLegion\Auth\Contract\PolicyInterface;
use MonkeysLegion\Auth\Exception\ForbiddenException;
use MonkeysLegion\Auth\Exception\PolicyNotFoundException;
use MonkeysLegion\Auth\RBAC\PermissionChecker;

/**
 * Service for checking authorization via policies and RBAC.
 */
final class AuthorizationService
{
    /** @var array<string, string> Map of model FQCN to policy FQCN */
    private array $policies = [];

    /** @var array<string, PolicyInterface> Cached policy instances */
    private array $policyInstances = [];

    public function __construct(
        private ?PermissionChecker $permissions = null,
    ) {}

    /**
     * Register a policy for a model class.
     */
    public function registerPolicy(string $modelClass, string $policyClass): self
    {
        $this->policies[$modelClass] = $policyClass;
        return $this;
    }

    /**
     * Register multiple policies from config.
     *
     * @param array<string, string> $policies
     */
    public function registerPolicies(array $policies): self
    {
        foreach ($policies as $model => $policy) {
            $this->registerPolicy($model, $policy);
        }
        return $this;
    }

    /**
     * Check if user is authorized for an ability on a model.
     */
    public function can(object $user, string $ability, ?object $model = null): bool
    {
        try {
            $this->authorize($user, $ability, $model);
            return true;
        } catch (ForbiddenException) {
            return false;
        }
    }

    /**
     * Check authorization and throw if denied.
     *
     * @throws ForbiddenException
     * @throws PolicyNotFoundException
     */
    public function authorize(object $user, string $ability, ?object $model = null): void
    {
        // 1. Check RBAC permissions first
        if ($this->permissions && $this->permissions->can($user, $ability)) {
            return;
        }

        // 2. If model provided, check policy
        if ($model !== null) {
            $this->authorizeViaPolicy($user, $ability, $model);
            return;
        }

        // 3. No model and no RBAC permission = check for global permission
        if ($this->permissions) {
            // Already checked above
            throw new ForbiddenException("Unauthorized", $ability);
        }

        // 4. No policy system, default allow for non-model abilities
    }

    /**
     * Authorize via model policy.
     *
     * @throws ForbiddenException
     * @throws PolicyNotFoundException
     */
    private function authorizeViaPolicy(object $user, string $ability, object $model): void
    {
        $policy = $this->resolvePolicy($model);

        // Check 'before' hook
        $before = $policy->before($user, $ability, $model);
        if ($before === true) {
            return;
        }
        if ($before === false) {
            throw new ForbiddenException("Unauthorized", $ability, get_class($model));
        }

        // Check specific ability method
        if (!method_exists($policy, $ability)) {
            throw new ForbiddenException(
                "Policy method '{$ability}' not defined",
                $ability,
                get_class($model)
            );
        }

        $result = $policy->{$ability}($user, $model);

        if ($result !== true) {
            throw new ForbiddenException("Unauthorized", $ability, get_class($model));
        }
    }

    /**
     * Resolve the policy for a model.
     *
     * @throws PolicyNotFoundException
     */
    private function resolvePolicy(object $model): PolicyInterface
    {
        $modelClass = get_class($model);

        // Check cache
        if (isset($this->policyInstances[$modelClass])) {
            return $this->policyInstances[$modelClass];
        }

        // Find policy class
        $policyClass = $this->policies[$modelClass] ?? null;

        // Try parent classes if not found
        if ($policyClass === null) {
            foreach (class_parents($model) as $parent) {
                if (isset($this->policies[$parent])) {
                    $policyClass = $this->policies[$parent];
                    break;
                }
            }
        }

        // Try interfaces if still not found
        if ($policyClass === null) {
            foreach (class_implements($model) as $interface) {
                if (isset($this->policies[$interface])) {
                    $policyClass = $this->policies[$interface];
                    break;
                }
            }
        }

        if ($policyClass === null) {
            throw new PolicyNotFoundException($modelClass);
        }

        // Instantiate and cache
        $policy = new $policyClass();
        $this->policyInstances[$modelClass] = $policy;

        return $policy;
    }

    /**
     * Check if user has a role.
     */
    public function hasRole(object $user, string $role): bool
    {
        if (!$user instanceof HasRolesInterface) {
            return false;
        }

        return $user->hasRole($role);
    }

    /**
     * Check if user has any of the given roles.
     *
     * @param string[] $roles
     */
    public function hasAnyRole(object $user, array $roles): bool
    {
        if (!$user instanceof HasRolesInterface) {
            return false;
        }

        return $user->hasAnyRole($roles);
    }

    /**
     * Check if user has all of the given roles.
     *
     * @param string[] $roles
     */
    public function hasAllRoles(object $user, array $roles): bool
    {
        if (!$user instanceof HasRolesInterface) {
            return false;
        }

        return $user->hasAllRoles($roles);
    }

    /**
     * Check if user has a permission.
     */
    public function hasPermission(object $user, string $permission): bool
    {
        return $this->permissions?->can($user, $permission) ?? false;
    }
}
