<?php

declare(strict_types=1);

namespace MonkeysLegion\Auth\Event;

final class PasswordResetRequested extends AuthEvent
{
    public function __construct(
        public readonly string $email,
        public readonly string $token,
        public readonly ?string $ipAddress = null,
    ) {
        parent::__construct();
    }

    public function getName(): string
    {
        return 'auth.password_reset_requested';
    }
}
