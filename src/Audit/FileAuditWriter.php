<?php
declare(strict_types=1);

namespace MonkeysLegion\Auth\Audit;

/**
 * MonKeysLegion Framework — Auth Package
 *
 * Writes audit entries as JSON lines to a daily-rotated log file.
 *
 * File naming: {log_path}/audit-{YYYY-MM-DD}.log
 * Format: one JSON object per line (JSONL).
 *
 * @copyright 2026 MonkeysCloud Team
 * @license   MIT
 */
final class FileAuditWriter implements AuditWriterInterface
{
    /**
     * @param string $logPath Directory for audit log files (e.g. storage/logs/audit).
     */
    public function __construct(
        private readonly string $logPath,
    ) {}

    public function write(AuditEntry $entry): void
    {
        if (!is_dir($this->logPath)) {
            @mkdir($this->logPath, 0o755, true);
        }

        $filename = $this->logPath . '/audit-' . date('Y-m-d') . '.log';
        $line     = $entry->toJson() . PHP_EOL;

        @file_put_contents($filename, $line, FILE_APPEND | LOCK_EX);
    }
}
