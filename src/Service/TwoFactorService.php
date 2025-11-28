<?php

declare(strict_types=1);

namespace MonkeysLegion\Auth\Service;

use MonkeysLegion\Auth\Contract\AuthenticatableInterface;
use MonkeysLegion\Auth\Contract\TwoFactorProviderInterface;
use MonkeysLegion\Auth\Event\TwoFactorDisabled;
use MonkeysLegion\Auth\Event\TwoFactorEnabled;
use MonkeysLegion\Auth\Exception\TwoFactorInvalidException;
use Psr\EventDispatcher\EventDispatcherInterface;

/**
 * Service for managing 2FA setup and verification.
 */
final class TwoFactorService
{
    public function __construct(
        private TwoFactorProviderInterface $provider,
        private ?EventDispatcherInterface $events = null,
        private string $issuer = 'MonkeysLegion',
    ) {}

    /**
     * Generate 2FA setup data for a user.
     *
     * @return array{secret: string, qr_code: string, provisioning_uri: string, recovery_codes: string[]}
     */
    public function generateSetup(string $accountName): array
    {
        $secret = $this->provider->generateSecret();
        $provisioningUri = $this->provider->getProvisioningUri(
            $secret,
            $accountName,
            $this->issuer
        );

        $recoveryCodes = $this->provider->generateRecoveryCodes(8);

        return [
            'secret' => $secret,
            'qr_code' => $this->provider->getQrCodeUri($provisioningUri),
            'provisioning_uri' => $provisioningUri,
            'recovery_codes' => $recoveryCodes,
        ];
    }

    /**
     * Verify and enable 2FA for a user.
     *
     * @throws TwoFactorInvalidException
     */
    public function enable(
        string $secret,
        string $code,
        int|string $userId,
        ?string $ipAddress = null,
    ): bool {
        if (!$this->provider->verify($secret, $code)) {
            throw new TwoFactorInvalidException('Invalid verification code');
        }

        // The actual storing of the secret should be handled by the application
        // This just validates the code is correct

        $this->dispatch(new TwoFactorEnabled($userId, $ipAddress));

        return true;
    }

    /**
     * Verify a 2FA code.
     */
    public function verify(string $secret, string $code): bool
    {
        return $this->provider->verify($secret, $code);
    }

    /**
     * Disable 2FA for a user.
     */
    public function disable(int|string $userId, ?string $ipAddress = null): void
    {
        // The actual clearing of the secret should be handled by the application

        $this->dispatch(new TwoFactorDisabled($userId, $ipAddress));
    }

    /**
     * Generate new recovery codes.
     *
     * @return string[]
     */
    public function regenerateRecoveryCodes(): array
    {
        return $this->provider->generateRecoveryCodes(8);
    }

    /**
     * Verify a recovery code.
     *
     * @param string[] $storedCodes
     * @return string[]|false The remaining codes if valid, false if invalid
     */
    public function verifyRecoveryCode(string $code, array $storedCodes): array|false
    {
        $code = strtoupper(trim($code));

        foreach ($storedCodes as $index => $stored) {
            // Use hash_equals to prevent timing attacks
            if (hash_equals(strtoupper($stored), $code)) {
                // Remove used code
                unset($storedCodes[$index]);
                return array_values($storedCodes);
            }
        }

        return false;
    }

    private function dispatch(object $event): void
    {
        $this->events?->dispatch($event);
    }
}
