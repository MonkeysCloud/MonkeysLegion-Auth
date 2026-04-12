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

namespace MonkeysLegion\Auth\Attribute;

use Attribute;

/**
 * Marks a route/controller method as requiring WebAuthn/passkey authentication.
 *
 * When the authentication middleware reads this attribute it will use the
 * 'webauthn' guard (WebAuthnGuard) to resolve the authenticated user.
 *
 * @example
 * #[Passkey]
 * public function checkout(): Response { ... }
 *
 * #[Passkey(userVerification: 'required')]
 * public function transferFunds(): Response { ... }
 */
#[Attribute(Attribute::TARGET_CLASS | Attribute::TARGET_METHOD)]
final readonly class Passkey
{
    public function __construct(
        /**
         * WebAuthn user-verification level.
         * One of: 'required', 'preferred', 'discouraged'.
         */
        public string $userVerification = 'preferred',
    ) {}
}
