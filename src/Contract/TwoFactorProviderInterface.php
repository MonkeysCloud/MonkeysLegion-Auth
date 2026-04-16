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

namespace MonkeysLegion\Auth\Contract;

/**
 * Contract for two-factor authentication providers (TOTP, etc.).
 */
interface TwoFactorProviderInterface
{
    /**
     * Generate a new secret key.
     */
    public function generateSecret(): string;

    /**
     * Verify a TOTP code against a secret.
     */
    public function verify(string $secret, string $code): bool;

    /**
     * Get the provisioning URI for authenticator apps.
     */
    public function getProvisioningUri(string $secret, string $email, string $issuer): string;

    /**
     * Generate backup/recovery codes.
     *
     * @return list<string>
     */
    public function generateBackupCodes(int $count = 8): array;
}
