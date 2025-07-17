<?php
declare(strict_types=1);

namespace MonkeysLegion\Auth\Middleware;

use MonkeysLegion\Auth\Attributes\Can;
use MonkeysLegion\Auth\AuthService\AuthorizationService;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Message\ResponseInterface;

/**
 * Authorization middleware that inspects #[Can] attributes and enforces policies,
 * but skips checks on configured public path patterns (supports globs via fnmatch).
 */
final class AuthorizationMiddleware implements MiddlewareInterface
{
    /**
     * @param AuthorizationService $authorization The authorization service
     * @param string[]             $publicPaths    Glob patterns of paths to bypass authorization
     */
    public function __construct(
        private AuthorizationService $authorization,
        private array $publicPaths = []
    ) {}

    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        $path = $request->getUri()->getPath();

        // 1) Bypass on any public pattern
        foreach ($this->publicPaths as $pattern) {
            // a) global wildcard
            if ($pattern === '*' || $pattern === '/*') {
                return $handler->handle($request);
            }

            // b) prefix wildcard ("/auth/*" → prefix "/auth/")
            if (str_ends_with($pattern, '*')) {
                $prefix = rtrim($pattern, '*');
                if (str_starts_with($path, $prefix)) {
                    return $handler->handle($request);
                }
            }

            // c) exact match
            if ($pattern === $path) {
                return $handler->handle($request);
            }

            // d) fallback fnmatch just in case
            if (fnmatch($pattern, $path, FNM_CASEFOLD)) {
                return $handler->handle($request);
            }
        }

        // Expect the route handler stored as attribute 'handler' => [ControllerClass, 'method']
        $handlerDef = $request->getAttribute('handler');
        if (is_array($handlerDef) && count($handlerDef) === 2) {
            [$class, $method] = $handlerDef;
            $refMethod  = new \ReflectionMethod($class, $method);
            $refClass   = $refMethod->getDeclaringClass();

            // Gather #[Can] from class and method
            $attrs = array_merge(
                $refClass->getAttributes(Can::class),
                $refMethod->getAttributes(Can::class)
            );

            foreach ($attrs as $attr) {
                /** @var Can $meta */
                $meta = $attr->newInstance();

                // Current user (injected by previous middleware)
                $user  = $request->getAttribute('user');

                // Model if specified
                $model = $meta->model ? $request->getAttribute('model') : null;

                // Throws exception on unauthorized
                $this->authorization->check($user, $meta->ability, $model);
            }
        }

        return $handler->handle($request);
    }
}