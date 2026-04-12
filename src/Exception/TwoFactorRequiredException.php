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

final class TwoFactorRequiredException extends AuthException
{
    public function __construct(
        public readonly string $challengeToken = '',
        string $message = 'Two-factor verification required.',
    ) {
        parent::__construct($message);
    }
}
