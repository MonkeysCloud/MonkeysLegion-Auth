<?php

declare(strict_types=1);

namespace MonkeysLegion\Auth\Middleware;

use MonkeysLegion\Auth\Contract\RateLimiterInterface;
use MonkeysLegion\Auth\Exception\RateLimitExceededException;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;

/**
 * PSR-15 rate limiting middleware.
 *
 * PERFORMANCE: Reads #[RateLimit] from route attributes for per-route config.
 * SECURITY: Uses client IP as default key to prevent abuse.
 */
final class RateLimitMiddleware implements MiddlewareInterface
{
    public function __construct(
        private readonly RateLimiterInterface $limiter,
        private readonly int $maxAttempts = 60,
        private readonly int $decaySeconds = 60,
    ) {}

    public function process(
        ServerRequestInterface $request,
        RequestHandlerInterface $handler,
    ): ResponseInterface {
        $maxAttempts  = (int) ($request->getAttribute('auth.rate_limit_max') ?? $this->maxAttempts);
        $decaySeconds = (int) ($request->getAttribute('auth.rate_limit_decay') ?? $this->decaySeconds);
        $customKey    = $request->getAttribute('auth.rate_limit_key');

        $key = is_string($customKey) && $customKey !== ''
            ? $customKey
            : 'rate:' . $this->resolveClientIp($request);

        if (!$this->limiter->attempt($key, $maxAttempts, $decaySeconds)) {
            $retryAfter = $this->limiter->availableIn($key);
            throw new RateLimitExceededException('Too many requests.', $retryAfter);
        }

        $remaining = $this->limiter->remaining($key, $maxAttempts);

        $response = $handler->handle($request);

        // Standard rate limit headers
        return $response
            ->withHeader('X-RateLimit-Limit', (string) $maxAttempts)
            ->withHeader('X-RateLimit-Remaining', (string) $remaining);
    }

    private function resolveClientIp(ServerRequestInterface $request): string
    {
        $serverParams = $request->getServerParams();

        // Trust X-Forwarded-For only if behind a known proxy
        return $serverParams['REMOTE_ADDR'] ?? '0.0.0.0';
    }
}
