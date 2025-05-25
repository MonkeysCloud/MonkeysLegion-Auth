<?php
declare(strict_types=1);

namespace MonkeysLegion\AuthService;

use MonkeysLegion\Auth\Policy\PolicyInterface;
use RuntimeException;

final class AuthorizationService
{
    /**
     * @var array<string,string>
     * Map of model FQCN to policy FQCN
     */
    private array $policies = [];

    /**
     * Register a policy for a given model class.
     *
     * @param string $modelClass  Fully qualified model class name
     * @param string $policyClass Fully qualified policy class name
     */
    public function registerPolicy(string $modelClass, string $policyClass): void
    {
        $this->policies[$modelClass] = $policyClass;
    }

    /**
     * Check authorization and throw if unauthorized.
     *
     * @param object      $user    The current user object
     * @param string      $ability The ability to check (e.g. 'edit')
     * @param object|null $model   The model instance (optional)
     *
     * @throws RuntimeException if no policy is registered or check fails
     */
    public function check(object $user, string $ability, ?object $model = null): void
    {
        // If a model is provided, resolve and invoke its policy
        if ($model !== null) {
            $modelClass  = get_class($model);
            $policyClass = $this->policies[$modelClass] ?? null;

            if ($policyClass === null) {
                throw new RuntimeException("No policy registered for {$modelClass}");
            }

            /** @var PolicyInterface $policy */
            $policy = new $policyClass();

            // 'before' hook: if returns bool, honor it directly
            $before = $policy->before($user, $ability, $model);
            if ($before !== null) {
                if ($before === false) {
                    throw new RuntimeException("Unauthorized");
                }
                return;
            }

            // Ensure the ability method exists
            if (!method_exists($policy, $ability)) {
                throw new RuntimeException("Policy {$policyClass}::{$ability} not defined");
            }

            // Invoke the ability method
            $allowed = $policy->{$ability}($user, $model);
            if ($allowed === false) {
                throw new RuntimeException("Unauthorized");
            }
            return;
        }

        // No model: global checks could go here (default allow)
    }
}