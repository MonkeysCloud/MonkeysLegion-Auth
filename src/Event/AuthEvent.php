<?php

declare(strict_types=1);

namespace MonkeysLegion\Auth\Event;

/**
 * Base class for authentication events.
 */
abstract class AuthEvent
{
    public readonly int $occurredAt;
    public array $metadata = [];

    public function __construct()
    {
        $this->occurredAt = time();
    }

    public function withMetadata(array $metadata): static
    {
        $this->metadata = array_merge($this->metadata, $metadata);
        return $this;
    }

    abstract public function getName(): string;
}
