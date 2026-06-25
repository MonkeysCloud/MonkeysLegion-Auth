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

use MonkeysLegion\Session\Contracts\SessionInterface;

/**
 * In-memory session implementation — for testing.
 */
final class InMemorySession implements SessionInterface
{
    /** @var array<string, mixed> */
    private array $data = [];
    private string $_id;
    private bool $_isStarted = true;

    public string $id {
        get => $this->_id;
        set { $this->_id = $value; }
    }

    public bool $isStarted {
        get => $this->_isStarted;
    }

    public function __construct()
    {
        $this->_id = bin2hex(random_bytes(16));
    }

    public function start(): bool
    {
        $this->_isStarted = true;
        return true;
    }

    public function regenerate(bool $destroy = false): bool
    {
        if ($destroy) {
            $this->data = [];
        }
        $this->_id = bin2hex(random_bytes(16));
        return true;
    }

    public function save(): bool
    {
        return true;
    }

    public function invalidate(): bool
    {
        $this->data = [];
        $this->_id = bin2hex(random_bytes(16));
        return true;
    }

    public function get(string $key, mixed $default = null): mixed
    {
        return $this->data[$key] ?? $default;
    }

    public function set(string $key, mixed $value): void
    {
        $this->data[$key] = $value;
    }

    public function has(string $key): bool
    {
        return array_key_exists($key, $this->data);
    }

    public function remove(string $key): void
    {
        unset($this->data[$key]);
    }

    public function pull(string $key, mixed $default = null): mixed
    {
        $value = $this->get($key, $default);
        $this->remove($key);
        return $value;
    }

    public function getName(): string
    {
        return 'ml_session';
    }

    public function forget(string $key): void
    {
        $this->remove($key);
    }

    public function getFlash(string $key, mixed $default = null): mixed
    {
        return $this->get($key, $default);
    }

    public function setIpAddress(?string $ip): void {}
    public function setUserAgent(?string $ua): void {}
    public function setUserId(string|int|null $id): void {}

    public function flash(string $key, mixed $value): void
    {
        $this->set($key, $value);
    }

    public function reflash(): void {}
    public function keep(string ...$keys): void {}
    public function now(string $key, mixed $value): void
    {
        $this->set($key, $value);
    }

    public function all(): array
    {
        return $this->data;
    }

    public function token(): string
    {
        return 'mock-csrf-token';
    }

    public function regenerateToken(): void {}
}
