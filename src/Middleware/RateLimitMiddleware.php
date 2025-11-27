<?php

declare(strict_types=1);

namespace MonkeysLegion\Auth\Middleware;

use MonkeysLegion\Auth\Contract\RateLimiterInterface;
use MonkeysLegion\Auth\Exception\RateLimitException;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;

/**
 * Rate limiting middleware.
 */
final class RateLimitMiddleware implements MiddlewareInterface
{
    /**
     * @param array<string, array{maxAttempts: int, decaySeconds: int}> $limits Per-path limits
     */
    public function __construct(
        private RateLimiterInterface $limiter,
        private int $defaultMaxAttempts = 60,
        private int $defaultDecaySeconds = 60,
        private array $limits = [],
        private ?\Closure $keyResolver = null,
        private ?\Closure $responseFactory = null,
    ) {}

    public function process(
        ServerRequestInterface $request,
        RequestHandlerInterface $handler,
    ): ResponseInterface {
        $key = $this->resolveKey($request);
        $path = $request->getUri()->getPath();

        // Get path-specific limits or use defaults
        $config = $this->getLimitsForPath($path);
        $maxAttempts = $config['maxAttempts'];
        $decaySeconds = $config['decaySeconds'];

        // Check rate limit
        if (!$this->limiter->attempt($key, $maxAttempts, $decaySeconds)) {
            $retryAfter = $this->limiter->availableIn($key);
            return $this->rateLimitResponse($retryAfter, $maxAttempts);
        }

        // Add rate limit headers to response
        $response = $handler->handle($request);
        $remaining = $this->limiter->remaining($key, $maxAttempts);

        return $response
            ->withHeader('X-RateLimit-Limit', (string) $maxAttempts)
            ->withHeader('X-RateLimit-Remaining', (string) max(0, $remaining - 1))
            ->withHeader('X-RateLimit-Reset', (string) (time() + $decaySeconds));
    }

    /**
     * Resolve the rate limit key for this request.
     */
    private function resolveKey(ServerRequestInterface $request): string
    {
        if ($this->keyResolver) {
            return ($this->keyResolver)($request);
        }

        // Default: use user ID if authenticated, otherwise IP
        $userId = $request->getAttribute('user_id');

        if ($userId) {
            return "user:{$userId}";
        }

        // Get client IP
        $ip = $request->getServerParams()['REMOTE_ADDR']
            ?? $request->getHeaderLine('X-Forwarded-For')
            ?? 'unknown';

        // Handle X-Forwarded-For (take first IP)
        if (str_contains($ip, ',')) {
            $ip = trim(explode(',', $ip)[0]);
        }

        return "ip:{$ip}";
    }

    /**
     * Get rate limits for a specific path.
     */
    private function getLimitsForPath(string $path): array
    {
        foreach ($this->limits as $pattern => $config) {
            if ($pattern === $path) {
                return [
                    'maxAttempts' => $config['maxAttempts'] ?? $this->defaultMaxAttempts,
                    'decaySeconds' => $config['decaySeconds'] ?? $this->defaultDecaySeconds,
                ];
            }

            if (str_ends_with($pattern, '*')) {
                $prefix = rtrim($pattern, '*');
                if (str_starts_with($path, $prefix)) {
                    return [
                        'maxAttempts' => $config['maxAttempts'] ?? $this->defaultMaxAttempts,
                        'decaySeconds' => $config['decaySeconds'] ?? $this->defaultDecaySeconds,
                    ];
                }
            }

            if (fnmatch($pattern, $path)) {
                return [
                    'maxAttempts' => $config['maxAttempts'] ?? $this->defaultMaxAttempts,
                    'decaySeconds' => $config['decaySeconds'] ?? $this->defaultDecaySeconds,
                ];
            }
        }

        return [
            'maxAttempts' => $this->defaultMaxAttempts,
            'decaySeconds' => $this->defaultDecaySeconds,
        ];
    }

    /**
     * Create rate limit exceeded response.
     */
    private function rateLimitResponse(int $retryAfter, int $limit): ResponseInterface
    {
        if ($this->responseFactory) {
            return ($this->responseFactory)(new RateLimitException(
                'Rate limit exceeded',
                $retryAfter
            ));
        }

        $body = json_encode([
            'error' => true,
            'message' => 'Too many requests',
            'retry_after' => $retryAfter,
        ], JSON_THROW_ON_ERROR);

        $response = new \Nyholm\Psr7\Response(429);
        $response->getBody()->write($body);

        return $response
            ->withHeader('Content-Type', 'application/json')
            ->withHeader('Retry-After', (string) $retryAfter)
            ->withHeader('X-RateLimit-Limit', (string) $limit)
            ->withHeader('X-RateLimit-Remaining', '0');
    }
}
