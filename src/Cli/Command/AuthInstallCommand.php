<?php

declare(strict_types=1);

namespace MonkeysLegion\Auth\Cli\Command;

use MonkeysLegion\Cli\Console\Attributes\Command as CommandAttr;
use MonkeysLegion\Cli\Console\Command;

/**
 * Publish the default auth migration into var/migrations.
 *
 * Usage:
 *   php ml auth:install
 *
 * This copies the stub SQL file from this package's resources/migrations
 * directory into your application's var/migrations directory with a
 * timestamped filename.
 */
#[CommandAttr('auth:install', 'Publish default auth tables migration')]
final class AuthInstallCommand extends Command
{
    public function __construct(
        private readonly string $migrationSourceDir = __DIR__ . '/../../../resources/migrations'
        // adjust relative path if your structure differs
    ) {
        parent::__construct();
    }

    /**
     * @param array<string> $argv
     */
    public function execute(array $argv): int
    {
        // 1. Resolve source stub
        $stub = $this->migrationSourceDir . '/0000_00_00_000000_auth_tables.sql';
        if (!\file_exists($stub)) {
            $this->error('Auth migration stub not found at: ' . $stub);
            return self::FAILURE;
        }

        // 2. Ensure target dir exists
        $targetDir = \base_path('var/migrations');
        if (!\is_dir($targetDir) && !\mkdir($targetDir, 0o775, true) && !\is_dir($targetDir)) {
            $this->error('Unable to create migrations directory: ' . $targetDir);
            return self::FAILURE;
        }

        // 3. Build timestamped filename
        $timestamp = \date('Y_m_d_His');
        $target = $targetDir . '/' . $timestamp . '_auth_tables.sql';

        // 4. Copy stub to destination
        if (!\copy($stub, $target)) {
            $this->error('Failed to publish auth migration into: ' . $target);
            return self::FAILURE;
        }

        $this->info('Published auth migration: ' . $target);
        return self::SUCCESS;
    }
}
