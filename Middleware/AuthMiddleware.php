<?php

declare(strict_types=1);

namespace MonkeysLegion\Auth\Middleware;

use MonkeysLegion\Auth\Contracts\RateLimiterInterface;
use MonkeysLegion\Auth\Contracts\TokenStorageInterface;
use MonkeysLegion\Auth\Contracts\UserProviderInterface;
use MonkeysLegion\Auth\Exception\InvalidTokenException;
use MonkeysLegion\Auth\Exception\RateLimitExceededException;
use MonkeysLegion\Auth\Exception\TokenExpiredException;
use MonkeysLegion\Auth\Exception\TokenRevokedException;
use MonkeysLegion\Auth\JwtService;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;

/**
 * Consolidated authentication middleware.
 * 
 * Handles:
 * - JWT token extraction and validation
 * - Token blacklist checking
 * - User loading
 * - Rate limiting (optional)
 * - Public path exclusions
 */
final class AuthMiddleware implements MiddlewareInterface
{
    /** @var callable */
    private $responseFactory;

    /**
     * @param JwtService               $jwt          JWT service
     * @param callable                 $responseFactory Factory: fn(int $status, array $data): ResponseInterface
     * @param string[]                 $publicPaths   Paths to exclude from auth (supports wildcards)
     * @param UserProviderInterface|null $users       Optional user provider
     * @param TokenStorageInterface|null $tokens      Optional token blacklist
     * @param RateLimiterInterface|null  $rateLimiter Optional rate limiter
     * @param int                        $rateLimit   Requests per minute (0 = disabled)
     */
    public function __construct(
        private readonly JwtService $jwt,
        callable $responseFactory,
        private readonly array $publicPaths = [],
        private readonly ?UserProviderInterface $users = null,
        private readonly ?TokenStorageInterface $tokens = null,
        private readonly ?RateLimiterInterface $rateLimiter = null,
        private readonly int $rateLimit = 0
    ) {
        $this->responseFactory = $responseFactory;
    }

    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        $path = $request->getUri()->getPath();

        // Check if public path
        if ($this->isPublicPath($path)) {
            // Still try to decode token if present (for optional auth)
            $request = $this->tryAttachUser($request);
            return $handler->handle($request);
        }

        // Rate limiting
        if ($this->rateLimiter !== null && $this->rateLimit > 0) {
            $key = $this->getRateLimitKey($request);
            if (!$this->rateLimiter->attempt($key, $this->rateLimit, 60)) {
                $retryAfter = $this->rateLimiter->retryAfter($key);
                return $this->errorResponse(429, 'Too many requests', $retryAfter);
            }
        }

        // Extract token
        $token = $this->extractToken($request);
        if ($token === null) {
            return $this->errorResponse(401, 'Missing authentication token');
        }

        // Validate token
        try {
            $claims = $this->jwt->decode($token);
        } catch (\RuntimeException $e) {
            $code = $e->getCode();
            if ($code === 401 && str_contains($e->getMessage(), 'expired')) {
                return $this->errorResponse(401, 'Token expired');
            }
            return $this->errorResponse(401, 'Invalid token');
        }

        // Check blacklist
        if ($this->tokens !== null && isset($claims['jti'])) {
            if ($this->tokens->isBlacklisted($claims['jti'])) {
                return $this->errorResponse(401, 'Token revoked');
            }
        }

        // Attach claims to request
        $userId = (int) ($claims['sub'] ?? $claims['uid'] ?? $claims['id'] ?? 0);
        $request = $request
            ->withAttribute('jwt_claims', $claims)
            ->withAttribute('user_id', $userId);

        // Load full user if provider available
        if ($this->users !== null && $userId > 0) {
            $user = $this->users->findById($userId);
            if ($user !== null) {
                // Verify token version if supported
                if (isset($claims['ver']) && method_exists($user, 'getTokenVersion')) {
                    if ((int) $claims['ver'] !== $user->getTokenVersion()) {
                        return $this->errorResponse(401, 'Token invalidated');
                    }
                }
                $request = $request->withAttribute('user', $user);
            }
        } else {
            // Use claims as user object
            $request = $request->withAttribute('user', (object) $claims);
        }

        return $handler->handle($request);
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

    private function extractToken(ServerRequestInterface $request): ?string
    {
        // Check Authorization header
        $auth = $request->getHeaderLine('Authorization');
        if (preg_match('/^Bearer\s+(.+)$/i', $auth, $matches)) {
            return $matches[1];
        }

        // Check query parameter (for websockets/SSE)
        $query = $request->getQueryParams();
        if (isset($query['token'])) {
            return $query['token'];
        }

        // Check cookie
        $cookies = $request->getCookieParams();
        if (isset($cookies['auth_token'])) {
            return $cookies['auth_token'];
        }

        return null;
    }

    private function tryAttachUser(ServerRequestInterface $request): ServerRequestInterface
    {
        $token = $this->extractToken($request);
        if ($token === null) {
            return $request;
        }

        try {
            $claims = $this->jwt->decode($token);
            $userId = (int) ($claims['sub'] ?? $claims['uid'] ?? $claims['id'] ?? 0);

            $request = $request
                ->withAttribute('jwt_claims', $claims)
                ->withAttribute('user_id', $userId);

            if ($this->users !== null && $userId > 0) {
                $user = $this->users->findById($userId);
                if ($user !== null) {
                    $request = $request->withAttribute('user', $user);
                }
            }
        } catch (\Throwable) {
            // Ignore errors on public paths
        }

        return $request;
    }

    private function getRateLimitKey(ServerRequestInterface $request): string
    {
        // Use user ID if authenticated, otherwise IP
        $userId = $request->getAttribute('user_id');
        if ($userId !== null && $userId > 0) {
            return 'auth:user:' . $userId;
        }

        $ip = $request->getServerParams()['REMOTE_ADDR'] ?? 'unknown';
        return 'auth:ip:' . $ip;
    }

    private function errorResponse(int $status, string $message, ?int $retryAfter = null): ResponseInterface
    {
        $data = ['error' => true, 'message' => $message];
        if ($retryAfter !== null) {
            $data['retry_after'] = $retryAfter;
        }

        return ($this->responseFactory)($status, $data);
    }
}
