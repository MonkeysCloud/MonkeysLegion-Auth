<?php

declare(strict_types=1);

namespace MonkeysLegion\Auth\TwoFactor;

use MonkeysLegion\Auth\Contract\TwoFactorProviderInterface;
use MonkeysLegion\Auth\Contract\UserProviderInterface;
use MonkeysLegion\Auth\Contract\EventDispatcherInterface;
use MonkeysLegion\Auth\Events\TwoFactorEnabled;
use MonkeysLegion\Auth\Exception\InvalidCredentialsException;

/**
 * Service for managing 2FA setup and verification.
 */
final class TwoFactorService
{
    public function __construct(
        private readonly TwoFactorProviderInterface $provider,
        private readonly UserProviderInterface $users,
        private readonly ?EventDispatcherInterface $events = null,
        private readonly string $issuer = 'MonkeysLegion'
    ) {}

    /**
     * Start 2FA setup for a user.
     *
     * @return array{secret: string, qr_uri: string, backup_codes: string[]}
     */
    public function beginSetup(int $userId, string $email): array
    {
        $secret = $this->provider->generateSecret();
        $qrUri = $this->provider->getProvisioningUri($secret, $email, $this->issuer);
        $backupCodes = $this->provider->generateBackupCodes();

        // Hash backup codes for storage
        $hashedCodes = array_map(
            fn(string $code) => $this->provider->hashBackupCode($code),
            $backupCodes
        );

        // Store pending setup (not activated until confirmed)
        // This would typically go in a cache/session
        return [
            'secret' => $secret,
            'qr_uri' => $qrUri,
            'backup_codes' => $backupCodes,
            'backup_codes_hashed' => $hashedCodes,
        ];
    }

    /**
     * Confirm and activate 2FA for a user.
     *
     * @param int      $userId       User ID
     * @param string   $secret       The secret from beginSetup
     * @param string   $code         TOTP code to verify
     * @param string[] $hashedCodes  Hashed backup codes
     *
     * @throws InvalidCredentialsException if code is invalid
     */
    public function confirmSetup(
        int $userId,
        string $secret,
        string $code,
        array $hashedCodes
    ): void {
        // Verify the code works with the secret
        if (!$this->provider->verify($secret, $code)) {
            throw new InvalidCredentialsException('Invalid 2FA code');
        }

        // Save to user
        $this->users->updateTwoFactor($userId, $secret, $hashedCodes);

        // Dispatch event
        $this->events?->dispatch(new TwoFactorEnabled($userId));
    }

    /**
     * Disable 2FA for a user.
     */
    public function disable(int $userId): void
    {
        $this->users->updateTwoFactor($userId, null, null);
    }

    /**
     * Verify a 2FA code.
     *
     * @param string $secret The user's 2FA secret
     * @param string $code   The code to verify
     */
    public function verify(string $secret, string $code): bool
    {
        return $this->provider->verify($secret, $code);
    }

    /**
     * Verify a backup code and consume it.
     *
     * @param int      $userId User ID
     * @param string   $code   Backup code to verify
     * @param string[] $hashes Current backup code hashes
     *
     * @return bool True if valid (code is consumed), false otherwise
     */
    public function verifyAndConsumeBackupCode(
        int $userId,
        string $code,
        array $hashes
    ): bool {
        $index = $this->provider->verifyBackupCode($code, $hashes);
        
        if ($index === false) {
            return false;
        }

        // Remove the used code
        unset($hashes[$index]);
        $hashes = array_values($hashes);

        // Get user's secret to preserve it
        $user = $this->users->findById($userId);
        if ($user === null) {
            return false;
        }

        // Update with remaining codes
        $this->users->updateTwoFactor(
            $userId,
            $user->getTwoFactorSecret(),
            $hashes
        );

        return true;
    }

    /**
     * Generate new backup codes for a user.
     *
     * @return string[] New backup codes (store hashed versions)
     */
    public function regenerateBackupCodes(int $userId): array
    {
        $user = $this->users->findById($userId);
        if ($user === null || !$user->isTwoFactorEnabled()) {
            throw new \RuntimeException('2FA not enabled');
        }

        $codes = $this->provider->generateBackupCodes();
        $hashes = array_map(
            fn(string $code) => $this->provider->hashBackupCode($code),
            $codes
        );

        $this->users->updateTwoFactor(
            $userId,
            $user->getTwoFactorSecret(),
            $hashes
        );

        return $codes;
    }
}
