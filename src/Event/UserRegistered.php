<?php

declare(strict_types=1);

namespace MonkeysLegion\Auth\Event;

use MonkeysLegion\Auth\Contract\AuthenticatableInterface;

final class UserRegistered extends AuthEvent
{
    public function __construct(
        public readonly AuthenticatableInterface $user,
        public readonly ?string $ipAddress = null,
    ) {
        parent::__construct();
    }

    public function getName(): string
    {
        return 'auth.user_registered';
    }
}
