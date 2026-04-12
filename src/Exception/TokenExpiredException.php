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

final class TokenExpiredException extends AuthException
{
    public function __construct(
        string $message = 'Token has expired.',
        array $context = [],
    ) {
        parent::__construct($message, $context);
    }
}
