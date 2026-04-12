<?php

declare(strict_types=1);

namespace MonkeysLegion\Auth\Exception;

final class ForbiddenException extends AuthException
{
    public function __construct(string $message = 'Forbidden.')
    {
        parent::__construct($message);
    }

    public function getStatusCode(): int
    {
        return 403;
    }
}
