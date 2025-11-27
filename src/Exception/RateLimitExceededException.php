<?php

declare(strict_types=1);

namespace MonkeysLegion\Auth\Exception;

/**
 * Thrown when rate limit is exceeded.
 */
final class RateLimitExceededException extends AuthException
{
    private int $retryAfter;

    public function __construct(
        int $retryAfter = 60,
        string $message = 'Too many requests',
        array $context = []
    ) {
        $this->retryAfter = $retryAfter;
        $context['retry_after'] = $retryAfter;
        
        parent::__construct($message, 429, null, $context);
    }

    public function getRetryAfter(): int
    {
        return $this->retryAfter;
    }
}
