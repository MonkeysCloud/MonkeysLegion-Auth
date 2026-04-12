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

final class TokenInvalidException extends AuthException
{
    public function __construct(
        string $message = 'Invalid token.',
        array $context = [],
    ) {
        parent::__construct($message, $context);
    }
}
