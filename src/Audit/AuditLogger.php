<?php
declare(strict_types=1);

namespace MonkeysLegion\Auth\Audit;

use MonkeysLegion\Auth\Event\AuthEvent;
use MonkeysLegion\Auth\Event\LoginSucceeded;
use MonkeysLegion\Auth\Event\LoginFailed;
use MonkeysLegion\Auth\Event\Logout;
use MonkeysLegion\Auth\Event\PasswordChanged;
use MonkeysLegion\Auth\Event\TokenRefreshed;
use MonkeysLegion\Auth\Event\PasskeyAuthenticated;
use MonkeysLegion\Auth\Event\UserRegistered;

/**
 * MonKeysLegion Framework — Auth Package
 *
 * Subscribes to all auth events and writes structured audit entries.
 *
 * SECURITY: Auth events never contain passwords or tokens. The audit
 * logger only records: event type, user ID, IP, user agent, and
 * correlation ID — enough for forensic analysis without exposing secrets.
 *
 * The registrar is a callable that receives (string $eventClass, callable $handler)
 * and wires it into the application's event system. This decouples the
 * AuditLogger from any specific event dispatcher implementation.
 *
 * Usage:
 *   $logger = new AuditLogger($writer);
 *   $logger->register(fn($event, $handler) => $provider->add($event, $handler));
 *
 * @copyright 2026 MonKeysCloud Team
 * @license   MIT
 */
final class AuditLogger
{
    /**
     * @param callable(string, callable): void $registrar
     */
    private $registrar;

    public function __construct(
        private readonly AuditWriterInterface $writer,
    ) {}

    /**
     * Register the audit logger as a listener for all auth events.
     *
     * @param callable(string, callable): void $registrar
     */
    public function register(callable $registrar): void
    {
        $this->registrar = $registrar;

        ($this->registrar)(LoginSucceeded::class, $this->onLoginSucceeded(...));
        ($this->registrar)(LoginFailed::class, $this->onLoginFailed(...));
        ($this->registrar)(Logout::class, $this->onLogout(...));
        ($this->registrar)(PasswordChanged::class, $this->onPasswordChanged(...));
        ($this->registrar)(TokenRefreshed::class, $this->onTokenRefreshed(...));
        ($this->registrar)(PasskeyAuthenticated::class, $this->onPasskeyAuthenticated(...));
        ($this->registrar)(UserRegistered::class, $this->onUserRegistered(...));
    }

    private function onLoginSucceeded(LoginSucceeded $event): void
    {
        $this->write(
            'login_succeeded',
            $event->user->getAuthIdentifier(),
            $event->ipAddress,
            $event->userAgent,
            $event->correlationId,
            ['guard' => $event->user::class],
        );
    }

    private function onLoginFailed(LoginFailed $event): void
    {
        $this->write(
            'login_failed',
            null,
            $event->ipAddress,
            $event->userAgent,
            $event->correlationId,
            ['email' => $event->email, 'reason' => $event->reason],
        );
    }

    private function onLogout(Logout $event): void
    {
        $this->write(
            'logout',
            $event->userId,
            $event->ipAddress,
            null,
            $event->correlationId,
            ['all_devices' => $event->allDevices],
        );
    }

    private function onPasswordChanged(PasswordChanged $event): void
    {
        $this->write(
            'password_changed',
            $event->userId,
            $event->ipAddress ?? null,
            null,
            $event->correlationId,
            [],
        );
    }

    private function onTokenRefreshed(TokenRefreshed $event): void
    {
        $this->write(
            'token_refreshed',
            $event->userId,
            $event->ipAddress ?? null,
            null,
            $event->correlationId,
            [],
        );
    }

    private function onPasskeyAuthenticated(PasskeyAuthenticated $event): void
    {
        $this->write(
            'passkey_authenticated',
            $event->userId,
            $event->ipAddress,
            $event->userAgent,
            $event->correlationId,
            ['credential_id' => $event->credentialId],
        );
    }

    private function onUserRegistered(UserRegistered $event): void
    {
        $this->write(
            'user_registered',
            $event->user->getAuthIdentifier(),
            $event->ipAddress,
            null,
            $event->correlationId,
            [],
        );
    }

    /**
     * Write an audit entry to the configured writer.
     */
    private function write(
        string $event,
        int|string|null $userId,
        ?string $ip,
        ?string $userAgent,
        string $correlationId,
        array $context = [],
    ): void {
        $this->writer->write(new AuditEntry(
            event: $event,
            userId: $userId,
            ip: $ip,
            userAgent: $userAgent,
            correlationId: $correlationId,
            context: $context,
        ));
    }
}
