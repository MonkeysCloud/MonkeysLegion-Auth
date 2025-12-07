<?php

declare(strict_types=1);

namespace MonkeysLegion\Auth\Exception;

/**
 * Thrown when a token has been revoked/blacklisted.
 */
final class TokenRevokedException extends AuthException
{
    public function __construct(
        string $message = 'Token has been revoked',
        array $context = []
    ) {
        parent::__construct($message, 401, null, $context);
    }
}
