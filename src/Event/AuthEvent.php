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

/**
 * Base auth event — all auth events extend this.
 *
 * SECURITY: Events provide an audit trail. Never include secrets/passwords.
 */
abstract class AuthEvent
{
    public readonly float $timestamp;
    public readonly string $correlationId;

    public function __construct()
    {
        $this->timestamp     = microtime(true);
        $this->correlationId = bin2hex(random_bytes(16));
    }
}
