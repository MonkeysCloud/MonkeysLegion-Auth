<?php

declare(strict_types=1);

namespace MonkeysLegion\Auth\Exception;

final class InvalidApiKeyException extends AuthException
{
    public function __construct(string $message = 'Invalid API key.')
    {
        parent::__construct($message);
    }
}
