<?php
declare(strict_types=1);

namespace MonkeysLegion\Auth\Middleware;

use MonkeysLegion\Auth\JwtService;
use MonkeysLegion\Http\Middleware\PathMatcher;
use MonkeysLegion\Http\Message\JsonResponse;
use MonkeysLegion\Mlc\Config;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Message\ResponseInterface;
use RuntimeException;


final class JwtUserMiddleware implements MiddlewareInterface
{
    public function __construct(
        private JwtService $jwt,
        private Config     $config
    ) {}

    /**
     * Processes the request to decode JWT and attach user information.
     *
     * @param ServerRequestInterface $req
     * @param RequestHandlerInterface $handler
     * @return ResponseInterface
     * @throws \JsonException
     */
    public function process(ServerRequestInterface $req,
                            RequestHandlerInterface $handler): ResponseInterface
    {
        $path   = $req->getUri()->getPath();
        $public = $this->config->get('auth.public_paths', []);
        $auth   = $req->getHeaderLine('Authorization');

        // 1) If there's a Bearer token, try to decode & attach it
        if (str_starts_with($auth, 'Bearer ')) {
            $token = substr($auth, 7);
            try {
                $claims = $this->jwt->decode($token);
                $userId = (int) ($claims['sub'] ?? $claims['uid'] ?? $claims['id'] ?? 0);

                // attach in all cases
                $req = $req
                    ->withAttribute('jwt_claims', $claims)
                    ->withAttribute('user_id',    $userId)
                    ->withAttribute('user',       $claims)
                ;
            } catch (RuntimeException $e) {
                // invalid or expired token
                // if this is a protected route, reject immediately
                if (! PathMatcher::isMatch($path, $public)) {
                    return new JsonResponse(
                        ['error' => true, 'message' => $e->getMessage()],
                        401
                    );
                }
                // else we swallow the error on public routes
            }
        }

        // 2) If it's a protected route and we still have no user_id, reject
        if (
            ! PathMatcher::isMatch($path, $public)
            && (int)$req->getAttribute('user_id', 0) <= 0
        ) {
            return new JsonResponse(
                ['error' => true, 'message' => 'Missing or invalid token'],
                401
            );
        }

        return $handler->handle($req);
    }
}