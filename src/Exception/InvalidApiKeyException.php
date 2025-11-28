<?php

declare(strict_types=1);

namespace MonkeysLegion\Auth\Exception;

/**
 * Thrown when API key is invalid or revoked.
 */
final class InvalidApiKeyException extends AuthException
{
    protected int $statusCode = 401;

    public function __construct(string $message = 'Invalid API key', array $context = [])
    {
        parent::__construct($message, 8001, null, $context);
    }
}
