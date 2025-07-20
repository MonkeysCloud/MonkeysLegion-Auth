<?php
declare(strict_types=1);

namespace MonkeysLegion\Auth\Middleware;

use MonkeysLegion\Auth\JwtService;
use MonkeysLegion\Http\Message\JsonResponse;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Message\ResponseInterface;
use RuntimeException;

final class JwtUserMiddleware implements MiddlewareInterface
{
    public function __construct(private JwtService $jwt) {}

    /**
     * Process the request to extract JWT claims and user ID.
     *
     * @param ServerRequestInterface $req
     * @param RequestHandlerInterface $handler
     * @return ResponseInterface
     * @throws \JsonException
     */
    public function process(ServerRequestInterface $req, RequestHandlerInterface $handler): ResponseInterface
    {
        $auth = $req->getHeaderLine('Authorization');
        if (! str_starts_with($auth, 'Bearer ')) {
            return new JsonResponse(['error'=>true,'message'=>'Missing token'], 401);
        }

        $token = substr($auth, 7);
        try {
            $claims = $this->jwt->decode($token);
        } catch (RuntimeException $e) {
            return new JsonResponse(['error'=>true,'message'=>'Invalid token'], 401);
        }

        // Attach both full claims and just the user ID
        $req = $req
            ->withAttribute('jwt_claims', $claims)
            ->withAttribute('user_id',   (int)($claims['sub'] ?? 0));

        return $handler->handle($req);
    }
}