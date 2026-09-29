<?php
declare(strict_types=1);

namespace Tests\Unit\Audit;

use MonkeysLegion\Auth\Audit\AuditEntry;
use MonkeysLegion\Auth\Audit\AuditLogger;
use MonkeysLegion\Auth\Audit\AuditWriterInterface;
use MonkeysLegion\Auth\Audit\FileAuditWriter;
use MonkeysLegion\Auth\Event\LoginFailed;
use MonkeysLegion\Auth\Event\LoginSucceeded;
use MonkeysLegion\Auth\Event\Logout;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

final class AuditLoggerTest extends TestCase
{
    #[Test]
    public function audit_entry_serializes_to_json(): void
    {
        $entry = new AuditEntry(
            event: 'login_succeeded',
            userId: 42,
            ip: '192.168.1.1',
            userAgent: 'Mozilla/5.0',
            correlationId: 'abc123',
            context: ['guard' => 'jwt'],
        );

        $json = $entry->toJson();
        $data = json_decode($json, true);

        self::assertSame('login_succeeded', $data['event']);
        self::assertSame(42, $data['user_id']);
        self::assertSame('192.168.1.1', $data['ip']);
        self::assertSame('abc123', $data['correlation_id']);
        self::assertSame(['guard' => 'jwt'], $data['context']);
    }

    #[Test]
    public function audit_entry_timestamp_is_set_automatically(): void
    {
        $entry = new AuditEntry(
            event: 'test',
            userId: null,
            ip: null,
            userAgent: null,
            correlationId: 'test',
        );

        self::assertGreaterThan(0, $entry->timestamp);
    }

    #[Test]
    public function audit_logger_registers_handlers(): void
    {
        $writer = new class implements AuditWriterInterface {
            public array $entries = [];
            public function write(AuditEntry $entry): void
            {
                $this->entries[] = $entry;
            }
        };

        $registeredEvents = [];
        $logger = new AuditLogger($writer);
        $logger->register(function (string $eventClass, callable $handler) use (&$registeredEvents) {
            $registeredEvents[] = $eventClass;
        });

        self::assertContains(LoginSucceeded::class, $registeredEvents);
        self::assertContains(LoginFailed::class, $registeredEvents);
        self::assertContains(Logout::class, $registeredEvents);
    }

    #[Test]
    public function file_audit_writer_writes_to_daily_file(): void
    {
        $tmpDir = sys_get_temp_dir() . '/ml_audit_test_' . uniqid();
        $writer = new FileAuditWriter($tmpDir);

        $entry = new AuditEntry(
            event: 'login_succeeded',
            userId: 1,
            ip: '127.0.0.1',
            userAgent: 'Test',
            correlationId: 'test-corr',
        );

        $writer->write($entry);

        $expectedFile = $tmpDir . '/audit-' . date('Y-m-d') . '.log';
        self::assertFileExists($expectedFile);

        $content = file_get_contents($expectedFile);
        self::assertIsString($content);
        self::assertStringContainsString('login_succeeded', $content);
        self::assertStringContainsString('"user_id":1', $content);

        // Cleanup
        @unlink($expectedFile);
        @rmdir($tmpDir);
    }
}
