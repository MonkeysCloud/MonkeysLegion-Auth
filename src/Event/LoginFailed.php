<?php

declare(strict_types=1);

/**
 * MonkeysLegion Auth v2
 *
 * @package   MonkeysLegion\Auth
 * @author    MonkeysCloud <jorge@monkeys.cloud>
 * @license   MIT
 *
 * @requires  PHP 8.4
 */

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
