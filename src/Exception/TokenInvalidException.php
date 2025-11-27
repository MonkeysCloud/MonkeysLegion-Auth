<?php

declare(strict_types=1);

namespace MonkeysLegion\Auth\Exception;

/**
 * Thrown when a JWT token is invalid (malformed, bad signature, etc).
 */
final class TokenInvalidException extends AuthException
{
    public function __construct(
        string $message = 'Invalid token',
        array $context = []
    ) {
        parent::__construct($message, 401, null, $context);
    }
}
