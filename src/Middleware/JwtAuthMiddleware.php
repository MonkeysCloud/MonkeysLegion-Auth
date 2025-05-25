<?php

declare(strict_types=1);

namespace MonkeysLegion\Auth\Middleware;

use MonkeysLegion\Auth\JwtService;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;

final class JwtAuthMiddleware implements MiddlewareInterface
{
    public function __construct(
        private JwtService                $jwt,
        private ResponseFactoryInterface $factory
    ) {}

    /**
     * @inheritDoc
     */
    public function process(
        ServerRequestInterface $request,
        RequestHandlerInterface $handler
    ): ResponseInterface {
        $auth = $request->getHeaderLine('Authorization');
        if (preg_match('/^Bearer\s+(.+)$/', $auth, $m)) {
            $payload = $this->jwt->verify($m[1]);
            $request = $request->withAttribute('userId', $payload->sub);
        }

        return $handler->handle($request);
    }
}