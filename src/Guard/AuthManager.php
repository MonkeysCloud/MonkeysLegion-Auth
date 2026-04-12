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

namespace MonkeysLegion\Auth\Guard;

use MonkeysLegion\Auth\Contract\GuardInterface;

/**
 * Guard registry — manages named guards and provides factory access.
 *
 * Usage:
 *   $manager->register('jwt', $jwtGuard);
 *   $manager->guard('jwt')->authenticate($request);
 *   $manager->guard()->authenticate($request); // uses default
 *
 * Uses PHP 8.4: property hooks.
 */
final class AuthManager
{
    /** @var array<string, GuardInterface> */
    private array $guards = [];

    /** Default guard name. */
    public string $defaultGuard {
        get => $this->_defaultGuard;
    }
    private string $_defaultGuard;

    public function __construct(string $defaultGuard = 'jwt')
    {
        $this->_defaultGuard = $defaultGuard;
    }

    /**
     * Register a named guard.
     */
    public function register(string $name, GuardInterface $guard): self
    {
        $this->guards[$name] = $guard;
        return $this;
    }

    /**
     * Get a guard by name (or the default).
     *
     * @throws \InvalidArgumentException If the guard is not registered.
     */
    public function guard(?string $name = null): GuardInterface
    {
        $name ??= $this->_defaultGuard;

        if (!isset($this->guards[$name])) {
            throw new \InvalidArgumentException("Guard '{$name}' is not registered.");
        }

        return $this->guards[$name];
    }

    /**
     * Check if a guard is registered.
     */
    public function has(string $name): bool
    {
        return isset($this->guards[$name]);
    }

    /**
     * Get all registered guard names.
     *
     * @return list<string>
     */
    public function getRegisteredGuards(): array
    {
        return array_keys($this->guards);
    }

    /**
     * Set the default guard name.
     */
    public function setDefaultGuard(string $name): void
    {
        $this->_defaultGuard = $name;
    }
}
