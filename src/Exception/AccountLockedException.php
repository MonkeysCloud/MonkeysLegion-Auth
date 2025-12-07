<?php

declare(strict_types=1);

namespace MonkeysLegion\Auth\Exception;

use DateTimeInterface;

/**
 * Thrown when an account is locked due to too many failed attempts.
 */
final class AccountLockedException extends AuthException
{
    private ?int $lockedUntil;

    public function __construct(
        string $message = 'Account is temporarily locked',
        int|DateTimeInterface|null $lockedUntil = null,
        array $context = []
    ) {
        if ($lockedUntil instanceof DateTimeInterface) {
            $this->lockedUntil = $lockedUntil->getTimestamp();
            $context['locked_until'] = $lockedUntil->format(DateTimeInterface::ATOM);
        } elseif (is_int($lockedUntil)) {
            $this->lockedUntil = $lockedUntil;
            $context['locked_until'] = $lockedUntil;
        } else {
            $this->lockedUntil = null;
        }

        parent::__construct($message, 423, null, $context);
    }

    public function getLockedUntil(): ?int
    {
        return $this->lockedUntil;
    }
}
