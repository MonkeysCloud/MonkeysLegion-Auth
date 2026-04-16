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

final class UserAlreadyExistsException extends AuthException
{
    public function __construct(string $message = 'User already exists.')
    {
        parent::__construct($message);
    }

    public function getStatusCode(): int
    {
        return 409;
    }
}
