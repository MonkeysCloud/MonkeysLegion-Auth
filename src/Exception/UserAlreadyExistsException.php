<?php

declare(strict_types=1);

namespace MonkeysLegion\Auth\Exception;

final class UserAlreadyExistsException extends AuthException
{
    public function __construct(string $message = 'User already exists.')
    {
        parent::__construct($message);
    }

    public function getStatusCode(): int
    {
        return 409;
    }
}
