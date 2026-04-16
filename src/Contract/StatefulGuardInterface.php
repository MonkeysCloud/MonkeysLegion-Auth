<?php

declare(strict_types=1);

/**
 * MonkeysLegion Auth v2
 *
 * @package   MonkeysLegion\Auth
 * @author    MonkeysCloud <jorge@monkeys.cloud>
 * @license   MIT
 *
 * @requires  PHP 8.4
 */

namespace MonkeysLegion\Auth\Contract;

/**
 * Contract for stateful guards that can log users in/out.
 *
 * Session-based guards implement this to manage login state.
 */
interface StatefulGuardInterface extends GuardInterface
{
    /**
     * Log a user in.
     */
    public function login(AuthenticatableInterface $user, bool $remember = false): void;

    /**
     * Log a user in by their identifier.
     */
    public function loginUsingId(int|string $id, bool $remember = false): ?AuthenticatableInterface;

    /**
     * Log the current user out.
     */
    public function logout(): void;

    /**
     * Check if the user was authenticated via remember-me.
     */
    public function viaRemember(): bool;
}
