<?php

declare(strict_types=1);

namespace MonkeysLegion\Auth\Exception;

final class RateLimitExceededException extends AuthException
{
    public function __construct(
        string $message = 'Too many attempts.',
        public readonly int $retryAfter = 0,
    ) {
        parent::__construct($message);
    }

    public function getStatusCode(): int
    {
        return 429;
    }
}
