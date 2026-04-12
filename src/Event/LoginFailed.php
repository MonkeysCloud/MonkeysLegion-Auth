<?php

declare(strict_types=1);

namespace MonkeysLegion\Auth\Event;

final class LoginFailed extends AuthEvent
{
    public function __construct(
        public readonly string $email,
        public readonly string $reason,
        public readonly ?string $ipAddress = null,
        public readonly ?string $userAgent = null,
    ) {
        parent::__construct();
    }
}
