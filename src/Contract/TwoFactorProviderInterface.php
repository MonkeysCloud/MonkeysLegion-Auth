<?php

declare(strict_types=1);

namespace MonkeysLegion\Auth\Contract;

/**
 * Contract for two-factor authentication providers.
 */
interface TwoFactorProviderInterface
{
    /**
     * Generate a new secret for the user.
     */
    public function generateSecret(): string;

    /**
     * Generate the provisioning URI for authenticator apps.
     */
    public function getProvisioningUri(string $secret, string $accountName, string $issuer): string;

    /**
     * Verify a TOTP code against the secret.
     */
    public function verify(string $secret, string $code): bool;

    /**
     * Generate a QR Code URI for the provisioning URI.
     */
    public function getQrCodeUri(string $uri): string;

    /**
     * Generate recovery codes.
     *
     * @return string[]
     */
    public function generateRecoveryCodes(int $count = 8): array;
}
