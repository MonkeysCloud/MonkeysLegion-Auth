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

namespace MonkeysLegion\Auth\Guard;

use MonkeysLegion\Auth\Contract\AuthenticatableInterface;
use MonkeysLegion\Auth\Contract\GuardInterface;
use Psr\Http\Message\ServerRequestInterface;

/**
 * Composite guard — tries multiple guards in order, first match wins.
 *
 * Inspired by Go middleware chains — compose different auth strategies.
 *
 * Usage:
 *   new CompositeGuard([new JwtGuard(...), new ApiKeyGuard(...)]);
 */
final class CompositeGuard implements GuardInterface
{
    private ?AuthenticatableInterface $_user  = null;
    private ?GuardInterface $_matchedGuard    = null;

    /**
     * @param list<GuardInterface> $guards Guards to try in order.
     */
    public function __construct(
        private readonly array $guards,
        private readonly string $_name = 'composite',
    ) {}

    public function name(): string
    {
        return $this->_matchedGuard?->name() ?? $this->_name;
    }

    public function authenticate(ServerRequestInterface $request): ?AuthenticatableInterface
    {
        foreach ($this->guards as $guard) {
            $user = $guard->authenticate($request);
            if ($user !== null) {
                $this->_user         = $user;
                $this->_matchedGuard = $guard;
                return $user;
            }
        }

        return null;
    }

    public function validate(array $credentials): bool
    {
        foreach ($this->guards as $guard) {
            if ($guard->validate($credentials)) {
                return true;
            }
        }

        return false;
    }

    public function user(): ?AuthenticatableInterface
    {
        return $this->_user;
    }

    public function id(): int|string|null
    {
        return $this->_user?->getAuthIdentifier();
    }

    public function check(): bool
    {
        return $this->_user !== null;
    }

    public function guest(): bool
    {
        return $this->_user === null;
    }

    /**
     * Get the guard that successfully authenticated.
     */
    public function matchedGuard(): ?GuardInterface
    {
        return $this->_matchedGuard;
    }
}
