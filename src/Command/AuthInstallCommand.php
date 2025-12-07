<?php

declare(strict_types=1);

namespace MonkeysLegion\Auth\Command;

use MonkeysLegion\Cli\Console\Attributes\Command as CommandAttr;
use MonkeysLegion\Cli\Console\Command;
use MonkeysLegion\Database\ConnectionManager;
use PDO;
use PDOException;

/**
 * Install MonkeysLegion Auth database tables
 * 
 * This command creates the required database tables for the Auth package:
 * - api_keys: For API key authentication
 * - oauth_accounts: For OAuth/social login
 * - token_blacklist: For JWT token revocation
 * - password_resets: For password reset functionality
 * 
 * Usage:
 *   php vendor/bin/ml auth:install              # Install tables
 *   php vendor/bin/ml auth:install --force      # Force reinstall
 *   php vendor/bin/ml auth:install --dry-run    # Show what would be created
 *   php vendor/bin/ml auth:install -v           # Verbose output
 */
#[CommandAttr('auth:install', 'Install MonkeysLegion Auth database tables')]
final class AuthInstallCommand extends Command
{
    private const TABLES = [
        'api_keys',
        'oauth_accounts',
        'token_blacklist',
        'password_resets',
    ];

    public function __construct(
        private readonly ConnectionManager $db,
    ) {}

    protected function handle(): int
    {
        $this->printHeader();

        try {
            $connection = $this->db->getConnection();

            // Check for prerequisites
            if (!$this->checkPrerequisites($connection)) {
                return self::FAILURE;
            }

            // Handle options
            $force = $this->hasOption('force') || $this->hasOption('f');
            $dryRun = $this->hasOption('dry-run');
            $verbose = $this->hasOption('v') || $this->hasOption('verbose');

            if ($dryRun) {
                return $this->handleDryRun($connection);
            }

            if ($force && !$this->confirmReinstall()) {
                $this->error('Installation cancelled.');
                return self::FAILURE;
            }

            return $this->installTables($connection, $force, $verbose);
        } catch (PDOException $e) {
            $this->handlePDOException($e);
            return self::FAILURE;
        } catch (\Exception $e) {
            $this->error('❌ Error: ' . $e->getMessage());
            if ($this->hasOption('v') || $this->hasOption('verbose')) {
                $this->error('Stack trace:');
                $this->error($e->getTraceAsString());
            }
            return self::FAILURE;
        }
    }

    private function printHeader(): void
    {
        $this->info('┌────────────────────────────────────────────┐');
        $this->info('│  MonkeysLegion Auth - Database Installer  │');
        $this->info('└────────────────────────────────────────────┘');
        $this->line('');
    }

    private function checkPrerequisites(PDO $connection): bool
    {
        // Check if users table exists
        if (!$this->tableExists($connection, 'users')) {
            $this->error('❌ Prerequisites not met!');
            $this->line('');
            $this->error('The "users" table does not exist.');
            $this->line('Please create your users table before installing auth tables.');
            $this->line('');
            $this->line('You can use the following SQL:');
            $this->line('');
            $this->line($this->getUsersTableExample());
            return false;
        }

        return true;
    }

    private function handleDryRun(PDO $connection): int
    {
        $this->info('🔍 Dry run mode - No changes will be made');
        $this->line('');

        foreach (self::TABLES as $tableName) {
            $exists = $this->tableExists($connection, $tableName);
            $status = $exists ? '✓ EXISTS' : '✗ MISSING';
            $action = $exists ? 'Skip' : 'Create';

            $this->line(sprintf(
                '  [%s] %s - Would %s',
                $status,
                str_pad($tableName, 20),
                $action
            ));
        }

        $this->line('');
        $this->line('Run without --dry-run to perform the installation.');

        return self::SUCCESS;
    }

    private function installTables(PDO $connection, bool $force, bool $verbose): int
    {
        $schemas = [
            'api_keys' => $this->getApiKeysSchema(),
            'oauth_accounts' => $this->getOAuthAccountsSchema(),
            'token_blacklist' => $this->getTokenBlacklistSchema(),
            'password_resets' => $this->getPasswordResetsSchema(),
        ];

        $installed = [];
        $skipped = [];
        $errors = [];

        foreach ($schemas as $tableName => $sql) {
            try {
                $result = $this->installTable($connection, $tableName, $sql, $force, $verbose);

                if ($result === 'installed') {
                    $installed[] = $tableName;
                } elseif ($result === 'skipped') {
                    $skipped[] = $tableName;
                }
            } catch (PDOException $e) {
                $errors[$tableName] = $e->getMessage();
                $this->error("❌ Failed to create '{$tableName}': {$e->getMessage()}");
            }
        }

        $this->printSummary($installed, $skipped, $errors);

        return empty($errors) ? self::SUCCESS : self::FAILURE;
    }

    private function installTable(
        PDO $connection,
        string $tableName,
        string $sql,
        bool $force,
        bool $verbose
    ): string {
        $exists = $this->tableExists($connection, $tableName);

        if ($exists && !$force) {
            $this->line("⏭️  Table '{$tableName}' already exists, skipping...");
            return 'skipped';
        }

        if ($force && $exists) {
            $this->line("🗑️  Dropping existing table '{$tableName}'...");
            if ($verbose) {
                $this->line("    SQL: DROP TABLE IF EXISTS `{$tableName}`");
            }
            $connection->exec("DROP TABLE IF EXISTS `{$tableName}`");
        }

        $this->line("📦 Creating table '{$tableName}'...");
        if ($verbose) {
            $this->line("    SQL: " . substr($sql, 0, 100) . '...');
        }

        $connection->exec($sql);

        if ($verbose) {
            $this->info("    ✓ Created successfully");
        }

        return 'installed';
    }

    private function printSummary(array $installed, array $skipped, array $errors): void
    {
        $this->line('');
        $this->info('═══════════════════════════════════════════');
        $this->info('  Installation Summary');
        $this->info('═══════════════════════════════════════════');

        if (!empty($installed)) {
            $this->info('');
            $this->info('✅ Successfully installed (' . count($installed) . '):');
            foreach ($installed as $table) {
                $this->line("   • {$table}");
            }
        }

        if (!empty($skipped)) {
            $this->line('');
            $this->line('⏭️  Skipped existing (' . count($skipped) . '):');
            foreach ($skipped as $table) {
                $this->line("   • {$table}");
            }
            if (!$this->hasOption('force')) {
                $this->line('');
                $this->line('💡 Tip: Use --force to reinstall existing tables');
            }
        }

        if (!empty($errors)) {
            $this->line('');
            $this->error('❌ Failed (' . count($errors) . '):');
            foreach ($errors as $table => $error) {
                $this->error("   • {$table}: {$error}");
            }
        }

        $this->line('');

        if (empty($errors)) {
            $this->info('🎉 Installation complete!');
            $this->line('');
            $this->line('Next steps:');
            $this->line('  1. Review your auth configuration');
            $this->line('  2. Set up your JWT secret in .env');
            $this->line('  3. Configure OAuth providers if needed');
        } else {
            $this->error('⚠️  Installation completed with errors');
            $this->line('Please check the error messages above and try again.');
        }
    }

    private function confirmReinstall(): bool
    {
        $this->line('');
        $this->error('╔════════════════════════════════════════════════════╗');
        $this->error('║  ⚠️  WARNING: DESTRUCTIVE OPERATION  ⚠️              ║');
        $this->error('╚════════════════════════════════════════════════════╝');
        $this->line('');
        $this->error('This will DROP and recreate the following tables:');
        foreach (self::TABLES as $table) {
            $this->error("  • {$table}");
        }
        $this->line('');
        $this->error('ALL DATA in these tables will be PERMANENTLY DELETED!');
        $this->line('');

        $response = $this->ask('Type "yes" to confirm');

        return strtolower(trim($response ?? '')) === 'yes';
    }

    private function handlePDOException(PDOException $e): void
    {
        $this->error('❌ Database error: ' . $e->getMessage());
        $this->line('');

        // Provide helpful error messages based on common issues
        $errorCode = $e->getCode();

        match (true) {
            str_contains($e->getMessage(), 'Access denied') => $this->line('💡 Check your database credentials in config/database.php'),
            str_contains($e->getMessage(), 'Unknown database') => $this->line('💡 Create the database first using: php vendor/bin/ml db:create'),
            str_contains($e->getMessage(), 'Connection refused') => $this->line('💡 Make sure your database server is running'),
            str_contains($e->getMessage(), 'foreign key constraint') => $this->line('💡 Make sure the users table exists before running this command'),
            default => $this->line('💡 Check your database configuration and permissions'),
        };
    }

    private function tableExists(PDO $connection, string $tableName): bool
    {
        try {
            $result = $connection->query("SHOW TABLES LIKE '{$tableName}'");
            return $result && $result->rowCount() > 0;
        } catch (PDOException $e) {
            return false;
        }
    }

    private function getUsersTableExample(): string
    {
        return <<<'SQL'
CREATE TABLE users (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    email VARCHAR(255) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    token_version INT UNSIGNED DEFAULT 1,
    email_verified_at TIMESTAMP NULL,
    two_factor_secret VARCHAR(255) NULL,
    two_factor_recovery_codes JSON NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
SQL;
    }

    private function getApiKeysSchema(): string
    {
        return <<<'SQL'
CREATE TABLE IF NOT EXISTS api_keys (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    user_id BIGINT UNSIGNED NOT NULL,
    name VARCHAR(255) NOT NULL,
    key_id VARCHAR(32) NOT NULL UNIQUE,
    key_hash VARCHAR(255) NOT NULL,
    scopes JSON NOT NULL,
    last_used_at TIMESTAMP NULL,
    expires_at TIMESTAMP NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_api_keys_user
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    INDEX idx_key_id (key_id),
    INDEX idx_user_id (user_id),
    INDEX idx_expires_at (expires_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
COMMENT='API keys for machine-to-machine authentication'
SQL;
    }

    private function getOAuthAccountsSchema(): string
    {
        return <<<'SQL'
CREATE TABLE IF NOT EXISTS oauth_accounts (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    user_id BIGINT UNSIGNED NOT NULL,
    provider VARCHAR(50) NOT NULL,
    provider_user_id VARCHAR(255) NOT NULL,
    access_token TEXT NULL,
    refresh_token TEXT NULL,
    expires_at TIMESTAMP NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_oauth_accounts_user
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    UNIQUE INDEX idx_provider_user (provider, provider_user_id),
    INDEX idx_user_id (user_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
COMMENT='OAuth/Social login account linkages'
SQL;
    }

    private function getTokenBlacklistSchema(): string
    {
        return <<<'SQL'
CREATE TABLE IF NOT EXISTS token_blacklist (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    token_id VARCHAR(64) NOT NULL UNIQUE,
    expires_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_token_blacklist_expires (expires_at),
    INDEX idx_token_id (token_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
COMMENT='Blacklisted JWT tokens (alternative to Redis)'
SQL;
    }

    private function getPasswordResetsSchema(): string
    {
        return <<<'SQL'
CREATE TABLE IF NOT EXISTS password_resets (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    user_id BIGINT UNSIGNED NOT NULL,
    token_hash VARCHAR(255) NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_password_resets_user
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    INDEX idx_password_resets_expires (expires_at),
    INDEX idx_user_id (user_id),
    INDEX idx_token_hash (token_hash)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
COMMENT='Password reset tokens'
SQL;
    }
}
