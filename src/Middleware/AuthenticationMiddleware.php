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

namespace MonkeysLegion\Auth\Middleware;

use MonkeysLegion\Auth\Attribute\Authenticated;
use MonkeysLegion\Auth\Attribute\Guard as GuardAttribute;
use MonkeysLegion\Auth\Guard\AuthManager;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;

/**
 * PSR-15 authentication middleware — guard-aware.
 *
 * Reads #[Guard] and #[Authenticated] attributes from route metadata.
 *
 * SECURITY: Unauthenticated requests receive 401 with no body details.
 */
final class AuthenticationMiddleware implements MiddlewareInterface
{
    public function __construct(
        private readonly AuthManager $manager,
        private readonly string $defaultGuard = 'jwt',
    ) {}

    public function process(
        ServerRequestInterface $request,
        RequestHandlerInterface $handler,
    ): ResponseInterface {
        // Determine which guard to use from request attributes
        $guardName = $this->resolveGuardName($request);
        $guard     = $this->manager->guard($guardName);

        $user = $guard->authenticate($request);

        if ($user !== null) {
            // Attach user and guard to request for downstream use
            $request = $request
                ->withAttribute('auth.user', $user)
                ->withAttribute('auth.guard', $guardName);
        }

        return $handler->handle($request);
    }

    private function resolveGuardName(ServerRequestInterface $request): string
    {
        // Check for guard attribute in route metadata
        $guardAttr = $request->getAttribute('auth.guard.name');
        if (is_string($guardAttr) && $guardAttr !== '') {
            return $guardAttr;
        }

        return $this->defaultGuard;
    }
}
