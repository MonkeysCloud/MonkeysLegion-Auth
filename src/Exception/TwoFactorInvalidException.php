<?php

declare(strict_types=1);

namespace MonkeysLegion\Auth\Exception;

/**
 * Thrown when 2FA code is invalid.
 */
final class TwoFactorInvalidException extends AuthException
{
    protected int $statusCode = 401;

    public function __construct(string $message = 'Invalid two-factor code', array $context = [])
    {
        parent::__construct($message, 401, null, $context);
    }
}
