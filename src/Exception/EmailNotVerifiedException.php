<?php

declare(strict_types=1);

namespace MonkeysLegion\Auth\Exception;

/**
 * Thrown when action requires a verified email.
 */
final class EmailNotVerifiedException extends AuthException
{
    public function __construct(
        string $message = 'Email verification required',
        array $context = []
    ) {
        parent::__construct($message, 403, null, $context);
    }
}
