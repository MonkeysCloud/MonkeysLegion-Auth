<?php
declare(strict_types=1);

namespace MonkeysLegion\Auth\Audit;

/**
 * MonKeysLegion Framework — Auth Package
 *
 * Contract for audit log persistence backends.
 *
 * @copyright 2026 MonkeysCloud Team
 * @license   MIT
 */
interface AuditWriterInterface
{
    /**
     * Write a single audit entry to the persistence backend.
     */
    public function write(AuditEntry $entry): void;
}
