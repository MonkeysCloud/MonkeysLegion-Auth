<?php

declare(strict_types=1);

namespace MonkeysLegion\Auth\Event;

final class TwoFactorEnabled extends AuthEvent
{
    public function __construct(
        public readonly int|string $userId,
        public readonly ?string $ipAddress = null,
    ) {
        parent::__construct();
    }

    public function getName(): string
    {
        return 'auth.2fa_enabled';
    }
}
