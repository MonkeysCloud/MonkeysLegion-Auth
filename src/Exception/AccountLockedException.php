<?php

declare(strict_types=1);

namespace MonkeysLegion\Auth\Exception;

final class AccountLockedException extends AuthException
{
    public function __construct(
        string $message = 'Account temporarily locked.',
        public readonly ?int $lockedUntil = null,
    ) {
        parent::__construct($message);
    }

    public function getStatusCode(): int
    {
        return 423;
    }
}
