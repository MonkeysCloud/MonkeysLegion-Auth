<?php

declare(strict_types=1);

namespace MonkeysLegion\Auth\Exception;

final class TokenExpiredException extends AuthException
{
    public function __construct(
        string $message = 'Token has expired.',
        array $context = [],
    ) {
        parent::__construct($message, $context);
    }
}
