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

use MonkeysLegion\Auth\Attribute\Authenticated;
use MonkeysLegion\Auth\Attribute\Guard as GuardAttribute;
use MonkeysLegion\Auth\Guard\AuthManager;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;

/**
 * PSR-15 authentication middleware — guard-aware.
 *
 * Reads #[Guard] and #[Authenticated] attributes from route metadata.
 *
 * SECURITY: Unauthenticated requests to protected routes receive 401.
 */
final class AuthenticationMiddleware implements MiddlewareInterface
{
    public function __construct(
        private readonly AuthManager $manager,
        private readonly ResponseFactoryInterface $responseFactory,
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
        } elseif ($this->isAuthRequired($request)) {
            // Protected route but no authenticated user → 401
            return $this->responseFactory->createResponse(401, 'Unauthorized');
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

    /**
     * Check if the route requires authentication.
     *
     * Routes are considered auth-required if they have the 'auth.required'
     * attribute set (typically by route metadata from #[Authenticated]).
     */
    private function isAuthRequired(ServerRequestInterface $request): bool
    {
        return (bool) $request->getAttribute('auth.required', false);
    }
}
