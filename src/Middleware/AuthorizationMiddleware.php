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

namespace MonkeysLegion\Auth\Middleware;

use MonkeysLegion\Auth\Contract\AuthenticatableInterface;
use MonkeysLegion\Auth\Contract\HasPermissionsInterface;
use MonkeysLegion\Auth\Contract\HasRolesInterface;
use MonkeysLegion\Auth\Exception\ForbiddenException;
use MonkeysLegion\Auth\Exception\UnauthorizedException;
use MonkeysLegion\Auth\Policy\Gate;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;

/**
 * PSR-15 authorization middleware — reads route attributes.
 *
 * Checks:
 * 1. User is authenticated
 * 2. #[RequiresRole] — role check
 * 3. #[RequiresPermission] — permission check
 * 4. #[Authorize] — Gate ability check
 *
 * SECURITY: Fails closed — missing user = 401.
 */
final class AuthorizationMiddleware implements MiddlewareInterface
{
    public function __construct(
        private readonly Gate $gate,
    ) {}

    public function process(
        ServerRequestInterface $request,
        RequestHandlerInterface $handler,
    ): ResponseInterface {
        $user = $request->getAttribute('auth.user');

        // Check required roles
        $requiredRoles = $request->getAttribute('auth.requires_roles');
        if (is_array($requiredRoles) && $requiredRoles !== []) {
            if (!$user instanceof AuthenticatableInterface) {
                throw new UnauthorizedException();
            }
            $this->checkRoles($user, $requiredRoles, $request->getAttribute('auth.roles_mode', 'any'));
        }

        // Check required permissions
        $requiredPerms = $request->getAttribute('auth.requires_permissions');
        if (is_array($requiredPerms) && $requiredPerms !== []) {
            if (!$user instanceof AuthenticatableInterface) {
                throw new UnauthorizedException();
            }
            $this->checkPermissions($user, $requiredPerms, $request->getAttribute('auth.permissions_mode', 'all'));
        }

        // Check Gate ability
        $ability = $request->getAttribute('auth.authorize_ability');
        if (is_string($ability) && $ability !== '') {
            $authUser = $user instanceof AuthenticatableInterface ? $user : null;
            $this->gate->authorize($authUser, $ability);
        }

        return $handler->handle($request);
    }

    private function checkRoles(AuthenticatableInterface $user, array $roles, string $mode): void
    {
        if (!$user instanceof HasRolesInterface) {
            throw new ForbiddenException('User does not support roles.');
        }

        $passes = match ($mode) {
            'all'   => $user->hasAllRoles($roles),
            default => $user->hasAnyRole($roles),
        };

        if (!$passes) {
            throw new ForbiddenException('Insufficient role.');
        }
    }

    private function checkPermissions(AuthenticatableInterface $user, array $permissions, string $mode): void
    {
        if (!$user instanceof HasPermissionsInterface) {
            throw new ForbiddenException('User does not support permissions.');
        }

        $passes = match ($mode) {
            'any'   => $user->hasAnyPermission($permissions),
            default => $user->hasAllPermissions($permissions),
        };

        if (!$passes) {
            throw new ForbiddenException('Insufficient permissions.');
        }
    }
}
