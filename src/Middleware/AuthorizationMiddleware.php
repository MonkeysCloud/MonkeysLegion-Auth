<?php
declare(strict_types=1);

namespace MonkeysLegion\Auth\Middleware;

use MonkeysLegion\Auth\Attributes\Can;
use MonkeysLegion\AuthService\AuthorizationService;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Message\ResponseInterface;

final class AuthorizationMiddleware implements MiddlewareInterface
{
    public function __construct(
        private AuthorizationService $authorization
    ) {}

    /**
     * Inspect #[Can(...)] on controller classes and methods,
     * and invoke the policy via AuthorizationService.
     */
    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        // Expect the route handler to have been stored as attribute 'handler'
        // and be an array: [ControllerClass::class, 'methodName']
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

                // Current user (injected earlier by JwtAuthMiddleware)
                $user  = $request->getAttribute('user');

                // If the policy is model‐based, pull model from request attribute 'model'
                $model = $meta->model
                    ? $request->getAttribute('model')
                    : null;

                // Throws on unauthorized
                $this->authorization->check($user, $meta->ability, $model);
            }
        }

        return $handler->handle($request);
    }
}