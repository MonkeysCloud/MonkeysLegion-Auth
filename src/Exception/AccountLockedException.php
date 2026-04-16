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
