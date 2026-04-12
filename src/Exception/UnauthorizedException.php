<?php

declare(strict_types=1);

namespace MonkeysLegion\Auth\Exception;

final class UnauthorizedException extends AuthException
{
    public function __construct(
        public readonly string $ability = '',
        public readonly ?string $modelClass = null,
        string $message = 'Unauthorized.',
    ) {
        parent::__construct($message);
    }

    public function getStatusCode(): int
    {
        return 403;
    }
}
