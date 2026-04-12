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

namespace MonkeysLegion\Auth\Policy;

use MonkeysLegion\Auth\Contract\AuthenticatableInterface;
use MonkeysLegion\Auth\Exception\UnauthorizedException;
use Closure;

/**
 * Authorization gate — ability and policy-based access control.
 *
 * Inspired by Laravel's Gate with additions:
 * - inspect() for detailed deny reasons
 * - forUser() for scoped checks
 *
 * SECURITY: Default-deny — undefined abilities are always denied.
 */
final class Gate
{
    /** @var array<string, Closure> */
    private array $abilities = [];

    /** @var array<string, string> Model FQCN → Policy FQCN */
    private array $policies = [];

    /** @var list<Closure> */
    private array $beforeCallbacks = [];

    /** @var list<Closure> */
    private array $afterCallbacks = [];

    // ── Definition ─────────────────────────────────────────────

    /**
     * Define an ability check.
     *
     * @param Closure(AuthenticatableInterface|null, mixed...): bool $callback
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
     * Register a before callback (super-admin bypass, etc.).
     */
    public function before(Closure $callback): self
    {
        $this->beforeCallbacks[] = $callback;
        return $this;
    }

    /**
     * Register an after callback.
     */
    public function after(Closure $callback): self
    {
        $this->afterCallbacks[] = $callback;
        return $this;
    }

    // ── Checking ───────────────────────────────────────────────

    /**
     * Check if user has an ability.
     */
    public function allows(?AuthenticatableInterface $user, string $ability, mixed ...$args): bool
    {
        // Run before callbacks
        foreach ($this->beforeCallbacks as $callback) {
            $result = $callback($user, $ability, ...$args);
            if ($result !== null) {
                return $this->runAfterCallbacks($user, $ability, (bool) $result, $args);
            }
        }

        // Check policy if model provided
        if ($args !== [] && is_object($args[0])) {
            $modelClass = $args[0]::class;

            if (isset($this->policies[$modelClass])) {
                $result = $this->callPolicy($user, $ability, $args[0]);
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
     * Check if user is denied an ability.
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
            $modelClass = ($args !== [] && is_object($args[0])) ? $args[0]::class : null;
            throw new UnauthorizedException($ability, $modelClass);
        }
    }

    /**
     * Inspect why a check passed or failed.
     *
     * @return array{allowed: bool, reason: string}
     */
    public function inspect(?AuthenticatableInterface $user, string $ability, mixed ...$args): array
    {
        // Before callbacks
        foreach ($this->beforeCallbacks as $callback) {
            $result = $callback($user, $ability, ...$args);
            if ($result !== null) {
                return [
                    'allowed' => (bool) $result,
                    'reason'  => $result ? 'Allowed by before callback.' : 'Denied by before callback.',
                ];
            }
        }

        // Policy
        if ($args !== [] && is_object($args[0])) {
            $modelClass = $args[0]::class;
            if (isset($this->policies[$modelClass])) {
                $result = $this->callPolicy($user, $ability, $args[0]);
                return [
                    'allowed' => $result,
                    'reason'  => $result
                        ? "Allowed by {$this->policies[$modelClass]}::{$ability}."
                        : "Denied by {$this->policies[$modelClass]}::{$ability}.",
                ];
            }
        }

        // Ability
        if (isset($this->abilities[$ability])) {
            $result = (bool) ($this->abilities[$ability])($user, ...$args);
            return [
                'allowed' => $result,
                'reason'  => $result ? 'Allowed by ability definition.' : 'Denied by ability definition.',
            ];
        }

        return ['allowed' => false, 'reason' => "Ability '{$ability}' is not defined."];
    }

    /**
     * Check multiple abilities (all must pass).
     *
     * @param list<string> $abilities
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
     * @param list<string> $abilities
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

    // ── Private ────────────────────────────────────────────────

    private function callPolicy(?AuthenticatableInterface $user, string $ability, object $model): bool
    {
        $policyClass = $this->policies[$model::class];

        /** @var object $policy */
        $policy = new $policyClass();

        // Check before hook on policy
        if (method_exists($policy, 'before')) {
            $before = $policy->before($user, $ability, $model);
            if ($before !== null) {
                return (bool) $before;
            }
        }

        if (!method_exists($policy, $ability)) {
            return false;
        }

        return (bool) $policy->{$ability}($user, $model);
    }

    /**
     * @param list<mixed> $args
     */
    private function runAfterCallbacks(
        ?AuthenticatableInterface $user,
        string $ability,
        bool $result,
        array $args,
    ): bool {
        foreach ($this->afterCallbacks as $callback) {
            $override = $callback($user, $ability, $result, ...$args);
            if ($override !== null) {
                $result = (bool) $override;
            }
        }
        return $result;
    }
}
