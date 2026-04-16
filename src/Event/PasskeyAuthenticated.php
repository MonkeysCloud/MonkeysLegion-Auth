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

namespace MonkeysLegion\Auth\Event;

/**
 * Dispatched after a user authenticates via WebAuthn/passkey.
 *
 * SECURITY: Carries credential ID for audit/forensics.
 * Never includes private key material or the raw assertion bytes.
 */
final class PasskeyAuthenticated extends AuthEvent
{
    public function __construct(
        public readonly int|string $userId,
        public readonly ?string $credentialId = null,
        public readonly ?string $ipAddress = null,
        public readonly ?string $userAgent = null,
    ) {
        parent::__construct();
    }
}
