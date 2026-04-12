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

final class Logout extends AuthEvent
{
    public function __construct(
        public readonly int|string $userId,
        public readonly bool $allDevices = false,
        public readonly ?string $ipAddress = null,
    ) {
        parent::__construct();
    }
}
