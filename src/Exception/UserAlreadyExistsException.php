<?php

declare(strict_types=1);

namespace MonkeysLegion\Auth\Exception;

/**
 * Thrown when trying to register a user that already exists.
 */
final class UserAlreadyExistsException extends AuthException
{
    protected int $statusCode = 409;

    public function __construct(string $message = 'User already exists', array $context = [])
    {
        parent::__construct($message, 409, null, $context);
    }
}
