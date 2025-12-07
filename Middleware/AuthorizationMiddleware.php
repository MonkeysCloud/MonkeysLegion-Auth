<?php

declare(strict_types=1);

namespace MonkeysLegion\Auth\Middleware;

use MonkeysLegion\Auth\Attributes\Can;
use MonkeysLegion\Auth\Attributes\RequireRole;
use MonkeysLegion\Auth\Attributes\RequirePermission;
use MonkeysLegion\Auth\Attributes\Authenticated;
use MonkeysLegion\Auth\Contracts\AuthenticatableInterface;
use MonkeysLegion\Auth\Exception\EmailNotVerifiedException;
use MonkeysLegion\Auth\Exception\UnauthorizedException;
use MonkeysLegion\Auth\Policy\Gate;
use MonkeysLegion\Auth\RBAC\RbacService;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;
use ReflectionMethod;

/**
 * Enhanced authorization middleware.
 * 
 * Processes:
 * - #[Authenticated] - Requires authentication
 * - #[RequireRole('admin')] - Requires specific roles
 * - #[RequirePermission('posts.edit')] - Requires specific permissions
 * - #[Can('edit', Post::class)] - Policy-based authorization
 */
final class AuthorizationMiddleware implements MiddlewareInterface
{
    /** @var callable */
    private $responseFactory;

    /**
     * @param callable           $responseFactory Factory: fn(int $status, array $data): ResponseInterface
     * @param Gate|null          $gate            Authorization gate
     * @param RbacService|null   $rbac            RBAC service
     * @param string[]           $publicPaths     Paths to skip authorization
     */
    public function __construct(
        callable $responseFactory,
        private readonly ?Gate $gate = null,
        private readonly ?RbacService $rbac = null,
        private readonly array $publicPaths = []
    ) {
        $this->responseFactory = $responseFactory;
    }

    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        $path = $request->getUri()->getPath();

        // Skip public paths
        if ($this->isPublicPath($path)) {
            return $handler->handle($request);
        }

        // Get handler definition
        $handlerDef = $request->getAttribute('handler');
        if (!is_array($handlerDef) || count($handlerDef) !== 2) {
            return $handler->handle($request);
        }

        [$class, $method] = $handlerDef;

        try {
            $refMethod = new ReflectionMethod($class, $method);
            $refClass = $refMethod->getDeclaringClass();

            // Merge class and method attributes
            $classAttrs = $refClass->getAttributes();
            $methodAttrs = $refMethod->getAttributes();
            $allAttrs = array_merge($classAttrs, $methodAttrs);

            $user = $request->getAttribute('user');

            foreach ($allAttrs as $attr) {
                $attrName = $attr->getName();

                // #[Authenticated]
                if ($attrName === Authenticated::class) {
                    $this->checkAuthenticated($user, $attr->newInstance());
                }

                // #[RequireRole]
                if ($attrName === RequireRole::class) {
                    $this->checkRoles($user, $attr->newInstance());
                }

                // #[RequirePermission]
                if ($attrName === RequirePermission::class) {
                    $this->checkPermissions($user, $attr->newInstance());
                }

                // #[Can]
                if ($attrName === Can::class) {
                    $this->checkPolicy($user, $attr->newInstance(), $request);
                }
            }
        } catch (UnauthorizedException $e) {
            return ($this->responseFactory)(403, $e->toArray());
        } catch (EmailNotVerifiedException $e) {
            return ($this->responseFactory)(403, $e->toArray());
        }

        return $handler->handle($request);
    }

    private function checkAuthenticated(?object $user, Authenticated $attr): void
    {
        if ($user === null) {
            throw new UnauthorizedException(message: 'Authentication required');
        }

        if ($attr->requireVerified && $user instanceof AuthenticatableInterface) {
            if (!$user->isEmailVerified()) {
                throw new EmailNotVerifiedException();
            }
        }

        if ($attr->require2FA && $user instanceof AuthenticatableInterface) {
            // This would typically be checked during login flow
            // Here we just verify 2FA is enabled
            if (!$user->isTwoFactorEnabled()) {
                throw new UnauthorizedException(message: 'Two-factor authentication required');
            }
        }
    }

    private function checkRoles(?object $user, RequireRole $attr): void
    {
        if ($this->rbac === null) {
            throw new \RuntimeException('RbacService required for #[RequireRole]');
        }

        if ($user === null) {
            throw new UnauthorizedException(message: 'Authentication required');
        }

        $userId = $user instanceof AuthenticatableInterface 
            ? (int) $user->getAuthIdentifier()
            : (int) ($user->id ?? $user->sub ?? 0);

        if (!$this->rbac->hasAnyRole($userId, $attr->roles)) {
            throw new UnauthorizedException(
                message: 'Required role: ' . implode(' or ', $attr->roles)
            );
        }
    }

    private function checkPermissions(?object $user, RequirePermission $attr): void
    {
        if ($this->rbac === null) {
            throw new \RuntimeException('RbacService required for #[RequirePermission]');
        }

        if ($user === null) {
            throw new UnauthorizedException(message: 'Authentication required');
        }

        $userId = $user instanceof AuthenticatableInterface 
            ? (int) $user->getAuthIdentifier()
            : (int) ($user->id ?? $user->sub ?? 0);

        if (!$this->rbac->hasAllPermissions($userId, $attr->permissions)) {
            throw new UnauthorizedException(
                message: 'Required permissions: ' . implode(', ', $attr->permissions)
            );
        }
    }

    private function checkPolicy(?object $user, Can $attr, ServerRequestInterface $request): void
    {
        if ($this->gate === null) {
            throw new \RuntimeException('Gate required for #[Can]');
        }

        $model = null;

        // Try to resolve model from request
        if ($attr->model !== null) {
            // Check if model is already attached
            $model = $request->getAttribute('model');

            // Or try to resolve from route parameter
            if ($model === null && $attr->routeParam !== null) {
                $modelId = $request->getAttribute($attr->routeParam);
                if ($modelId !== null) {
                    // Model resolution would need to be implemented
                    // This is a placeholder for the pattern
                    $model = $request->getAttribute('resolved_' . $attr->model);
                }
            }
        }

        $authUser = $user instanceof AuthenticatableInterface ? $user : null;

        if ($model !== null) {
            $this->gate->authorize($authUser, $attr->ability, $model);
        } else {
            $this->gate->authorize($authUser, $attr->ability);
        }
    }

    private function isPublicPath(string $path): bool
    {
        foreach ($this->publicPaths as $pattern) {
            if ($pattern === '*' || $pattern === '/*') {
                return true;
            }

            if (str_ends_with($pattern, '*')) {
                $prefix = rtrim($pattern, '*');
                if (str_starts_with($path, $prefix)) {
                    return true;
                }
            }

            if ($pattern === $path) {
                return true;
            }

            if (fnmatch($pattern, $path, FNM_CASEFOLD)) {
                return true;
            }
        }

        return false;
    }
}
