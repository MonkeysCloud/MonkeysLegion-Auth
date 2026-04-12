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

namespace MonkeysLegion\Auth\Contract;

use Psr\Http\Message\ServerRequestInterface;

/**
 * Contract for authentication guards.
 *
 * Guards are responsible for authenticating incoming requests
 * using different strategies (JWT, session, API key, etc.).
 *
 * Inspired by Laravel's Guard contract and Go middleware chains.
 */
interface GuardInterface
{
    /**
     * Get the guard name identifier.
     */
    public function name(): string;

    /**
     * Attempt to authenticate the incoming request.
     *
     * @return AuthenticatableInterface|null The authenticated user, or null.
     */
    public function authenticate(ServerRequestInterface $request): ?AuthenticatableInterface;

    /**
     * Validate credentials without persisting auth state.
     *
     * @param array<string, mixed> $credentials
     */
    public function validate(array $credentials): bool;

    /**
     * Get the currently authenticated user.
     */
    public function user(): ?AuthenticatableInterface;

    /**
     * Get the authenticated user's identifier.
     */
    public function id(): int|string|null;

    /**
     * Check if a user is authenticated.
     */
    public function check(): bool;

    /**
     * Check if the current request is from a guest (unauthenticated).
     */
    public function guest(): bool;
}
