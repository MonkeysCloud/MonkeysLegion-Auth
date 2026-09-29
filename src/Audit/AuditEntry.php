<?php
declare(strict_types=1);

namespace MonkeysLegion\Auth\Audit;

/**
 * MonKeysLegion Framework — Auth Package
 *
 * Immutable audit log entry.
 *
 * SECURITY: Never contains passwords, tokens, or other secrets.
 *
 * @copyright 2026 MonkeysCloud Team
 * @license   MIT
 */
final readonly class AuditEntry
{
    /**
     * @param string      $event         Event type (login_succeeded, login_failed, etc.).
     * @param int|string|null $userId    Acting user ID (null for failed login attempts).
     * @param string|null $ip            Client IP address.
     * @param string|null $userAgent     Client user agent.
     * @param string      $correlationId Correlation ID for distributed tracing.
     * @param array<string, mixed> $context Additional context (never secrets).
     * @param float       $timestamp     Unix timestamp with microseconds.
     */
    public function __construct(
        public string $event,
        public int|string|null $userId,
        public ?string $ip,
        public ?string $userAgent,
        public string $correlationId,
        public array $context = [],
        public float $timestamp = 0.0,
    ) {
        if ($this->timestamp === 0.0) {
            $this->timestamp = microtime(true);
        }
    }

    /**
     * Serialize to a JSON line for file logging.
     */
    public function toJson(): string
    {
        return json_encode([
            'timestamp'      => date('c', (int) $this->timestamp),
            'event'          => $this->event,
            'user_id'        => $this->userId,
            'ip'             => $this->ip,
            'user_agent'     => $this->userAgent,
            'correlation_id' => $this->correlationId,
            'context'        => $this->context,
        ], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    }
}
