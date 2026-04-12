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

namespace MonkeysLegion\Auth\Storage;

use MonkeysLegion\Auth\Contract\SessionInterface;

/**
 * In-memory session implementation — for testing.
 */
final class InMemorySession implements SessionInterface
{
    /** @var array<string, mixed> */
    private array $data = [];
    private string $id;

    public function __construct()
    {
        $this->id = bin2hex(random_bytes(16));
    }

    public function get(string $key, mixed $default = null): mixed
    {
        return $this->data[$key] ?? $default;
    }

    public function put(string $key, mixed $value): void
    {
        $this->data[$key] = $value;
    }

    public function forget(string $key): void
    {
        unset($this->data[$key]);
    }

    public function has(string $key): bool
    {
        return array_key_exists($key, $this->data);
    }

    public function regenerate(bool $destroy = false): bool
    {
        if ($destroy) {
            $this->data = [];
        }
        $this->id = bin2hex(random_bytes(16));
        return true;
    }

    public function invalidate(): bool
    {
        $this->data = [];
        $this->id   = bin2hex(random_bytes(16));
        return true;
    }

    public function getId(): string
    {
        return $this->id;
    }
}
