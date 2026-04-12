<?php

declare(strict_types=1);

/**
 * MonkeysLegion Auth v2
 *
 * @package   MonkeysLegion\Auth
 * @author    MonkeysCloud <jorge@monkeyscloud.com>
 * @license   MIT
 *
 * @requires  PHP 8.4
 */

namespace MonkeysLegion\Auth\Exception;

final class TokenRevokedException extends AuthException
{
    public function __construct(
        string $message = 'Token has been revoked.',
        array $context = [],
    ) {
        parent::__construct($message, $context);
    }
}
