<?php

declare(strict_types=1);

namespace MonkeysLegion\Auth\Event;

final class Logout extends AuthEvent
{
    public function __construct(
        public readonly int|string $userId,
        public readonly bool $allDevices = false,
        public readonly ?string $ipAddress = null,
    ) {
        parent::__construct();
    }

    public function getName(): string
    {
        return 'auth.logout';
    }
}
