<?php

declare(strict_types=1);

/**
 * MonkeysLegion Auth v2
 *
 * @package   MonkeysLegion\Auth
 * @author    MonkeysCloud <jorge@monkeys.cloud>
 * @license   MIT
 *
 * @requires  PHP 8.4
 */

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
    /**
     * @param list<string> $trustedProxies IP addresses of trusted reverse proxies.
     *                                     X-Forwarded-For is only honoured when the
     *                                     direct client (REMOTE_ADDR) is in this list.
     */
    public function __construct(
        private readonly RateLimiterInterface $limiter,
        private readonly int $maxAttempts = 60,
        private readonly int $decaySeconds = 60,
        private readonly array $trustedProxies = [],
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
        $remoteAddr   = $serverParams['REMOTE_ADDR'] ?? '0.0.0.0';

        // Trust X-Forwarded-For only when the direct client is a configured trusted proxy.
        // This prevents arbitrary IP spoofing by untrusted clients.
        if ($this->trustedProxies !== [] && in_array($remoteAddr, $this->trustedProxies, true)) {
            $forwarded = $request->getHeaderLine('X-Forwarded-For');
            if ($forwarded !== '') {
                // Left-most entry is the original client; skip any trusted proxy IPs.
                $ips = array_map('trim', explode(',', $forwarded));
                foreach ($ips as $ip) {
                    if (!in_array($ip, $this->trustedProxies, true)) {
                        return $ip;
                    }
                }
            }
        }

        return $remoteAddr;
    }
}
