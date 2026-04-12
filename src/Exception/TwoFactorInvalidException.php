<?php

declare(strict_types=1);

namespace MonkeysLegion\Auth\Exception;

final class TwoFactorInvalidException extends AuthException
{
    public function __construct(string $message = 'Invalid two-factor code.')
    {
        parent::__construct($message);
    }
}
