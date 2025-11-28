<?php

declare(strict_types=1);

namespace MonkeysLegion\Auth\Middleware;

use MonkeysLegion\Auth\Attribute\Authenticated;
use MonkeysLegion\Auth\Attribute\Can;
use MonkeysLegion\Auth\Attribute\RequiresPermission;
use MonkeysLegion\Auth\Attribute\RequiresRole;
use MonkeysLegion\Auth\Contract\HasRolesInterface;
use MonkeysLegion\Auth\Exception\ForbiddenException;
use MonkeysLegion\Auth\Exception\UnauthorizedException;
use MonkeysLegion\Auth\RBAC\PermissionChecker;
use MonkeysLegion\Auth\Service\AuthorizationService;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;
use ReflectionClass;
use ReflectionMethod;

/**
 * Authorization middleware that enforces attribute-based access control.
 *
 * Supports:
 * - #[Can('ability', Model::class)]
 * - #[RequiresRole('admin')]
 * - #[RequiresPermission('posts.create')]
 * - #[Authenticated]
 */
final class AuthorizationMiddleware implements MiddlewareInterface
{
    /**
     * @param string[] $publicPaths
     */
    public function __construct(
        private AuthorizationService $authorization,
        private ?PermissionChecker $permissions = null,
        private array $publicPaths = [],
        private ?\Closure $responseFactory = null,
    ) {}

    public function process(
        ServerRequestInterface $request,
        RequestHandlerInterface $handler,
    ): ResponseInterface {
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
            $this->checkAuthorization($request, $class, $method);
        } catch (UnauthorizedException|ForbiddenException $e) {
            return $this->errorResponse($e);
        }

        return $handler->handle($request);
    }

    /**
     * Check all authorization attributes.
     */
    private function checkAuthorization(
        ServerRequestInterface $request,
        string $class,
        string $method,
    ): void {
        $refClass = new ReflectionClass($class);
        $refMethod = new ReflectionMethod($class, $method);

        $user = $request->getAttribute('user');

        // Gather attributes from class and method
        $this->checkAuthenticatedAttribute($refClass, $refMethod, $user);
        $this->checkRoleAttributes($refClass, $refMethod, $user);
        $this->checkPermissionAttributes($refClass, $refMethod, $user);
        $this->checkCanAttributes($refClass, $refMethod, $request, $user);
    }

    /**
     * Check #[Authenticated] attribute.
     */
    private function checkAuthenticatedAttribute(
        ReflectionClass $class,
        ReflectionMethod $method,
        ?object $user,
    ): void {
        $attrs = array_merge(
            $class->getAttributes(Authenticated::class),
            $method->getAttributes(Authenticated::class)
        );

        if (empty($attrs)) {
            return;
        }

        if ($user === null) {
            throw new UnauthorizedException();
        }
    }

    /**
     * Check #[RequiresRole] attributes.
     */
    private function checkRoleAttributes(
        ReflectionClass $class,
        ReflectionMethod $method,
        ?object $user,
    ): void {
        $attrs = array_merge(
            $class->getAttributes(RequiresRole::class),
            $method->getAttributes(RequiresRole::class)
        );

        if (empty($attrs)) {
            return;
        }

        if ($user === null) {
            throw new UnauthorizedException();
        }

        if (!$user instanceof HasRolesInterface) {
            throw new ForbiddenException('User does not support roles');
        }

        foreach ($attrs as $attr) {
            /** @var RequiresRole $meta */
            $meta = $attr->newInstance();

            $hasRole = $meta->anyOf
                ? $user->hasAnyRole($meta->roles)
                : $user->hasAllRoles($meta->roles);

            if (!$hasRole) {
                throw new ForbiddenException(
                    'Missing required role(s): ' . implode(', ', $meta->roles)
                );
            }
        }
    }

    /**
     * Check #[RequiresPermission] attributes.
     */
    private function checkPermissionAttributes(
        ReflectionClass $class,
        ReflectionMethod $method,
        ?object $user,
    ): void {
        $attrs = array_merge(
            $class->getAttributes(RequiresPermission::class),
            $method->getAttributes(RequiresPermission::class)
        );

        if (empty($attrs) || !$this->permissions) {
            return;
        }

        if ($user === null) {
            throw new UnauthorizedException();
        }

        foreach ($attrs as $attr) {
            /** @var RequiresPermission $meta */
            $meta = $attr->newInstance();

            $hasPermission = $meta->anyOf
                ? $this->permissions->canAny($user, $meta->permissions)
                : $this->permissions->canAll($user, $meta->permissions);

            if (!$hasPermission) {
                throw new ForbiddenException(
                    'Missing required permission(s): ' . implode(', ', $meta->permissions)
                );
            }
        }
    }

    /**
     * Check #[Can] attributes.
     */
    private function checkCanAttributes(
        ReflectionClass $class,
        ReflectionMethod $method,
        ServerRequestInterface $request,
        ?object $user,
    ): void {
        $attrs = array_merge(
            $class->getAttributes(Can::class),
            $method->getAttributes(Can::class)
        );

        if (empty($attrs)) {
            return;
        }

        if ($user === null) {
            throw new UnauthorizedException();
        }

        foreach ($attrs as $attr) {
            /** @var Can $meta */
            $meta = $attr->newInstance();

            // Get model from request if specified
            $model = $meta->model ? $request->getAttribute('model') : null;

            // This will throw ForbiddenException if unauthorized
            $this->authorization->authorize($user, $meta->ability, $model);
        }
    }

    /**
     * Check if path matches any public pattern.
     */
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

    /**
     * Create error response.
     */
    private function errorResponse(\Throwable $e): ResponseInterface
    {
        if ($this->responseFactory) {
            return ($this->responseFactory)($e);
        }

        $statusCode = match (true) {
            $e instanceof UnauthorizedException => 401,
            $e instanceof ForbiddenException => 403,
            default => 500,
        };

        $body = json_encode([
            'error' => true,
            'message' => $e->getMessage(),
            'code' => $e->getCode(),
        ], JSON_THROW_ON_ERROR);

        $response = new \Nyholm\Psr7\Response($statusCode);
        $response->getBody()->write($body);

        return $response->withHeader('Content-Type', 'application/json');
    }
}
