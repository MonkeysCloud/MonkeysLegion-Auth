<?php

declare(strict_types=1);

namespace MonkeysLegion\Auth\Exception;

final class InvalidCredentialsException extends AuthException
{
    public function __construct(
        string $message = 'Invalid credentials.',
        array $context = [],
    ) {
        parent::__construct($message, $context);
    }
}
