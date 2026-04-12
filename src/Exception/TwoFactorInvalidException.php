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

final class TwoFactorInvalidException extends AuthException
{
    public function __construct(string $message = 'Invalid two-factor code.')
    {
        parent::__construct($message);
    }
}
