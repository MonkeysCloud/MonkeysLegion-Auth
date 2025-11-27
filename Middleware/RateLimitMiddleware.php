<?php

declare(strict_types=1);

namespace MonkeysLegion\Auth\Middleware;

use MonkeysLegion\Auth\Attributes\RateLimit;
use MonkeysLegion\Auth\Contracts\RateLimiterInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;
use ReflectionMethod;

/**
 * Rate limiting middleware using #[RateLimit] attributes.
 */
final class RateLimitMiddleware implements MiddlewareInterface
{
    /** @var callable */
    private $responseFactory;

    public function __construct(
        private readonly RateLimiterInterface $limiter,
        callable $responseFactory,
        private readonly int $defaultMaxAttempts = 60,
        private readonly int $defaultDecaySeconds = 60
    ) {
        $this->responseFactory = $responseFactory;
    }

    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        $handlerDef = $request->getAttribute('handler');
        
        $maxAttempts = $this->defaultMaxAttempts;
        $decaySeconds = $this->defaultDecaySeconds;
        $keyType = 'ip';

        // Check for #[RateLimit] attribute
        if (is_array($handlerDef) && count($handlerDef) === 2) {
            [$class, $method] = $handlerDef;

            try {
                $refMethod = new ReflectionMethod($class, $method);
                $refClass = $refMethod->getDeclaringClass();

                // Check method first, then class
                $attrs = $refMethod->getAttributes(RateLimit::class);
                if (empty($attrs)) {
                    $attrs = $refClass->getAttributes(RateLimit::class);
                }

                if (!empty($attrs)) {
                    /** @var RateLimit $attr */
                    $attr = $attrs[0]->newInstance();
                    $maxAttempts = $attr->maxAttempts;
                    $decaySeconds = $attr->decaySeconds;
                    $keyType = $attr->key;
                }
            } catch (\Throwable) {
                // Use defaults
            }
        }

        // Build rate limit key
        $key = $this->buildKey($keyType, $request);

        // Check rate limit
        if (!$this->limiter->attempt($key, $maxAttempts, $decaySeconds)) {
            $retryAfter = $this->limiter->retryAfter($key);
            
            $response = ($this->responseFactory)(429, [
                'error' => true,
                'message' => 'Too many requests',
                'retry_after' => $retryAfter,
            ]);

            return $response
                ->withHeader('Retry-After', (string) $retryAfter)
                ->withHeader('X-RateLimit-Limit', (string) $maxAttempts)
                ->withHeader('X-RateLimit-Remaining', '0');
        }

        // Add rate limit headers to response
        $remaining = $this->limiter->remaining($key, $maxAttempts);
        
        $response = $handler->handle($request);
        
        return $response
            ->withHeader('X-RateLimit-Limit', (string) $maxAttempts)
            ->withHeader('X-RateLimit-Remaining', (string) $remaining);
    }

    private function buildKey(string $type, ServerRequestInterface $request): string
    {
        $path = $request->getUri()->getPath();
        $method = $request->getMethod();
        $base = "rate:{$method}:{$path}:";

        return match ($type) {
            'ip' => $base . $this->getClientIp($request),
            'user' => $base . 'user:' . ($request->getAttribute('user_id') ?? 'guest'),
            'ip+user' => $base . $this->getClientIp($request) . ':' . ($request->getAttribute('user_id') ?? 'guest'),
            default => $base . $type, // Custom key
        };
    }

    private function getClientIp(ServerRequestInterface $request): string
    {
        $serverParams = $request->getServerParams();

        // Check forwarded headers (for reverse proxies)
        $forwardedFor = $request->getHeaderLine('X-Forwarded-For');
        if ($forwardedFor !== '') {
            $ips = array_map('trim', explode(',', $forwardedFor));
            return $ips[0];
        }

        $realIp = $request->getHeaderLine('X-Real-IP');
        if ($realIp !== '') {
            return $realIp;
        }

        return $serverParams['REMOTE_ADDR'] ?? 'unknown';
    }
}
