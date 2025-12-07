<?php

declare(strict_types=1);

namespace MonkeysLegion\Auth\Policy;

use MonkeysLegion\Auth\Contract\AuthenticatableInterface;
use MonkeysLegion\Auth\Exception\UnauthorizedException;
use Closure;

/**
 * Authorization gate for checking abilities.
 */
final class Gate
{
    /** @var array<string, Closure> */
    private array $abilities = [];

    /** @var array<string, string> Model FQCN to Policy FQCN */
    private array $policies = [];

    /** @var Closure[] */
    private array $beforeCallbacks = [];

    /** @var Closure[] */
    private array $afterCallbacks = [];

    /**
     * Define an ability check.
     *
     * @param string  $ability  The ability name
     * @param Closure $callback Callback receiving (user, ...args) returning bool
     */
    public function define(string $ability, Closure $callback): self
    {
        $this->abilities[$ability] = $callback;
        return $this;
    }

    /**
     * Register a policy for a model class.
     */
    public function policy(string $modelClass, string $policyClass): self
    {
        $this->policies[$modelClass] = $policyClass;
        return $this;
    }

    /**
     * Register a before callback (runs before all checks).
     */
    public function before(Closure $callback): self
    {
        $this->beforeCallbacks[] = $callback;
        return $this;
    }

    /**
     * Register an after callback (runs after all checks).
     */
    public function after(Closure $callback): self
    {
        $this->afterCallbacks[] = $callback;
        return $this;
    }

    /**
     * Check if user has ability.
     *
     * @param AuthenticatableInterface|null $user    The user (null for guests)
     * @param string                        $ability The ability to check
     * @param mixed                         ...$args Arguments (typically the model)
     */
    public function allows(?AuthenticatableInterface $user, string $ability, mixed ...$args): bool
    {
        // Run before callbacks
        foreach ($this->beforeCallbacks as $callback) {
            $result = $callback($user, $ability, ...$args);
            if ($result !== null) {
                return $this->runAfterCallbacks($user, $ability, $result, $args);
            }
        }

        // Check policy if model provided
        if (!empty($args) && is_object($args[0])) {
            $model = $args[0];
            $modelClass = get_class($model);

            if (isset($this->policies[$modelClass])) {
                $result = $this->callPolicy($user, $ability, $model);
                return $this->runAfterCallbacks($user, $ability, $result, $args);
            }
        }

        // Check defined abilities
        if (isset($this->abilities[$ability])) {
            $result = (bool) ($this->abilities[$ability])($user, ...$args);
            return $this->runAfterCallbacks($user, $ability, $result, $args);
        }

        // Default deny
        return $this->runAfterCallbacks($user, $ability, false, $args);
    }

    /**
     * Check if user is denied ability.
     */
    public function denies(?AuthenticatableInterface $user, string $ability, mixed ...$args): bool
    {
        return !$this->allows($user, $ability, ...$args);
    }

    /**
     * Check and throw if denied.
     *
     * @throws UnauthorizedException
     */
    public function authorize(?AuthenticatableInterface $user, string $ability, mixed ...$args): void
    {
        if ($this->denies($user, $ability, ...$args)) {
            $modelClass = null;
            if (!empty($args) && is_object($args[0])) {
                $modelClass = get_class($args[0]);
            }

            throw new UnauthorizedException($ability, $modelClass);
        }
    }

    /**
     * Check multiple abilities (all must pass).
     *
     * @param string[] $abilities
     */
    public function all(?AuthenticatableInterface $user, array $abilities, mixed ...$args): bool
    {
        foreach ($abilities as $ability) {
            if ($this->denies($user, $ability, ...$args)) {
                return false;
            }
        }
        return true;
    }

    /**
     * Check multiple abilities (any must pass).
     *
     * @param string[] $abilities
     */
    public function any(?AuthenticatableInterface $user, array $abilities, mixed ...$args): bool
    {
        foreach ($abilities as $ability) {
            if ($this->allows($user, $ability, ...$args)) {
                return true;
            }
        }
        return false;
    }

    private function callPolicy(?AuthenticatableInterface $user, string $ability, object $model): bool
    {
        $modelClass = get_class($model);
        $policyClass = $this->policies[$modelClass];

        /** @var PolicyInterface $policy */
        $policy = new $policyClass();

        // Check before hook
        $before = $policy->before($user, $ability, $model);
        if ($before !== null) {
            return $before;
        }

        // Check ability method
        if (!method_exists($policy, $ability)) {
            return false;
        }

        return (bool) $policy->{$ability}($user, $model);
    }

    private function runAfterCallbacks(
        ?AuthenticatableInterface $user,
        string $ability,
        bool $result,
        array $args
    ): bool {
        foreach ($this->afterCallbacks as $callback) {
            $override = $callback($user, $ability, $result, ...$args);
            if ($override !== null) {
                $result = $override;
            }
        }
        return $result;
    }
}
