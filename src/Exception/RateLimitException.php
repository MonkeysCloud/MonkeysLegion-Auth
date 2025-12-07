<?php

declare(strict_types=1);

namespace MonkeysLegion\Auth\Exception;

/**
 * Thrown when rate limit is exceeded.
 */
final class RateLimitException extends AuthException
{
    protected int $statusCode = 429;

    public function __construct(
        string $message = 'Rate limit exceeded',
        int $retryAfter = 60,
        array $context = []
    ) {
        $context['retry_after'] = $retryAfter;
        parent::__construct($message, 429, null, $context);
    }

    public function getRetryAfter(): int
    {
        return $this->context['retry_after'] ?? 60;
    }
}
