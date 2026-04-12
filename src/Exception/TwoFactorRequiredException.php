<?php

declare(strict_types=1);

namespace MonkeysLegion\Auth\Exception;

final class TwoFactorRequiredException extends AuthException
{
    public function __construct(
        public readonly string $challengeToken = '',
        string $message = 'Two-factor verification required.',
    ) {
        parent::__construct($message);
    }
}
