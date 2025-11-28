<?php

declare(strict_types=1);

namespace MonkeysLegion\Auth\Exception;

use Exception;
use Throwable;

/**
 * Base exception for all authentication/authorization errors.
 */
class AuthException extends Exception
{
    protected array $context = [];

    public function __construct(
        string $message = 'Authentication error',
        int $code = 401,
        ?Throwable $previous = null,
        array $context = []
    ) {
        parent::__construct($message, $code, $previous);
        $this->context = $context;
    }

    public function getContext(): array
    {
        return $this->context;
    }

    public function __clone(): void
    {
        // Allow cloning by implementing this magic method
    }

    public function withContext(array $context): static
    {
        $newContext = array_merge($this->context, $context);
        return new static($this->getMessage(), $this->getCode(), $this->getPrevious(), $newContext);
    }

    public function toArray(): array
    {
        return [
            'error' => true,
            'type' => static::class,
            'message' => $this->getMessage(),
            'code' => $this->getCode(),
            'context' => $this->context,
        ];
    }
}
