<?php

declare(strict_types=1);

namespace MonkeysLegion\Auth\Middleware;

use MonkeysLegion\Auth\ApiKey\ApiKeyService;
use MonkeysLegion\Auth\Contract\UserProviderInterface;
use MonkeysLegion\Auth\Exception\InvalidApiKeyException;
use MonkeysLegion\Auth\Exception\TokenExpiredException;
use MonkeysLegion\Auth\Exception\TokenInvalidException;
use MonkeysLegion\Auth\Exception\TokenRevokedException;
use MonkeysLegion\Auth\Exception\UnauthorizedException;
use MonkeysLegion\Auth\Service\AuthService;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;

/**
 * Unified authentication middleware supporting JWT and API keys.
 *
 * Attaches user info to request attributes:
 * - 'user': The authenticated user object
 * - 'user_id': The user identifier
 * - 'jwt_claims': JWT claims (if JWT auth)
 * - 'api_key': API key record (if API key auth)
 */
final class AuthenticationMiddleware implements MiddlewareInterface
{
    /**
     * @param string[] $publicPaths Glob patterns for public paths
     */
    public function __construct(
        private AuthService $auth,
        private UserProviderInterface $users,
        private ?ApiKeyService $apiKeys = null,
        private array $publicPaths = [],
        private ?\Closure $responseFactory = null,
    ) {}

    public function process(
        ServerRequestInterface $request,
        RequestHandlerInterface $handler,
    ): ResponseInterface {
        $path = $request->getUri()->getPath();

        // Check if path is public
        if ($this->isPublicPath($path)) {
            // Still try to authenticate, but don't require it
            $request = $this->tryAuthenticate($request);
            return $handler->handle($request);
        }

        // Protected path - authentication required
        try {
            $request = $this->authenticate($request);
        } catch (UnauthorizedException | TokenExpiredException | TokenInvalidException | TokenRevokedException | InvalidApiKeyException $e) {
            return $this->unauthorizedResponse($e);
        }

        return $handler->handle($request);
    }

    /**
     * Attempt authentication (required).
     */
    private function authenticate(ServerRequestInterface $request): ServerRequestInterface
    {
        // Try JWT first
        $auth = $request->getHeaderLine('Authorization');

        if (str_starts_with($auth, 'Bearer ')) {
            return $this->authenticateJwt($request, substr($auth, 7));
        }

        // Try JWT from query param
        $queryParams = $request->getQueryParams();
        if (isset($queryParams['token'])) {
            return $this->authenticateJwt($request, $queryParams['token']);
        }

        // Try JWT from cookie
        $cookies = $request->getCookieParams();
        if (isset($cookies['auth_token'])) {
            return $this->authenticateJwt($request, $cookies['auth_token']);
        }

        // Try API key
        if ($this->apiKeys && str_starts_with($auth, 'ApiKey ')) {
            return $this->authenticateApiKey($request, substr($auth, 7));
        }

        // Check X-API-Key header
        $apiKeyHeader = $request->getHeaderLine('X-API-Key');
        if ($this->apiKeys && $apiKeyHeader) {
            return $this->authenticateApiKey($request, $apiKeyHeader);
        }

        throw new UnauthorizedException('Missing authentication');
    }

    /**
     * Try to authenticate (optional - for public paths).
     */
    private function tryAuthenticate(ServerRequestInterface $request): ServerRequestInterface
    {
        try {
            return $this->authenticate($request);
        } catch (\Throwable) {
            return $request;
        }
    }

    /**
     * Authenticate via JWT.
     */
    private function authenticateJwt(ServerRequestInterface $request, string $token): ServerRequestInterface
    {
        $claims = $this->auth->validateAccessToken($token);
        $userId = $claims['sub'] ?? null;

        $user = $userId ? $this->users->findById($userId) : null;

        if (!$user) {
            throw new TokenInvalidException('User not found');
        }

        return $request
            ->withAttribute('user', $user)
            ->withAttribute('user_id', $userId)
            ->withAttribute('jwt_claims', $claims);
    }

    /**
     * Authenticate via API key.
     */
    private function authenticateApiKey(ServerRequestInterface $request, string $key): ServerRequestInterface
    {
        $record = $this->apiKeys->validate($key);
        $userId = $record['user_id'] ?? null;

        $user = $userId ? $this->users->findById($userId) : null;

        if (!$user) {
            throw new InvalidApiKeyException('User not found');
        }

        return $request
            ->withAttribute('user', $user)
            ->withAttribute('user_id', $userId)
            ->withAttribute('api_key', $record);
    }

    /**
     * Check if path matches any public path pattern.
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
     * Create unauthorized response.
     */
    private function unauthorizedResponse(\Throwable $e): ResponseInterface
    {
        if ($this->responseFactory) {
            return ($this->responseFactory)($e);
        }

        // Default JSON response
        $body = json_encode([
            'error' => true,
            'message' => $e->getMessage(),
            'code' => $e->getCode(),
        ], JSON_THROW_ON_ERROR);

        $response = new \Nyholm\Psr7\Response(401);
        $response->getBody()->write($body);

        return $response->withHeader('Content-Type', 'application/json');
    }
}
