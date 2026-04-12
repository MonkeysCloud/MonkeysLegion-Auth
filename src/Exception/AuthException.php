<?php

declare(strict_types=1);

namespace MonkeysLegion\Auth\Exception;

/**
 * Base exception for all auth errors.
 *
 * SECURITY: Context data is for logging only — never exposed to clients.
 */
class AuthException extends \RuntimeException
{
    /**
     * @param array<string, mixed> $context Contextual data for logging.
     */
    public function __construct(
        string $message = 'Authentication error.',
        public readonly array $context = [],
        int $code = 0,
        ?\Throwable $previous = null,
    ) {
        parent::__construct($message, $code, $previous);
    }

    /**
     * HTTP status code for this error.
     */
    public function getStatusCode(): int
    {
        return 401;
    }
}
