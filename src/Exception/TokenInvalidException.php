<?php

declare(strict_types=1);

namespace MonkeysLegion\Auth\Exception;

final class TokenInvalidException extends AuthException
{
    public function __construct(
        string $message = 'Invalid token.',
        array $context = [],
    ) {
        parent::__construct($message, $context);
    }
}
