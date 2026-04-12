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

namespace MonkeysLegion\Auth\Guard;

use MonkeysLegion\Auth\Contract\AuthenticatableInterface;
use MonkeysLegion\Auth\Contract\GuardInterface;
use MonkeysLegion\Auth\Contract\UserProviderInterface;
use Psr\Http\Message\ServerRequestInterface;

/**
 * WebAuthn/Passkey guard — authenticates via pre-verified passkey assertions.
 *
 * This guard reads the user identifier from a request attribute that must be
 * set by the WebAuthn verification layer (e.g. a controller or middleware that
 * calls MonkeysLegion\WebAuthn\Service\WebAuthnService::verifyAuthentication()).
 *
 * Integration pattern:
 *   1. Client calls navigator.credentials.get()
 *   2. Server verifies the assertion with WebAuthnService::verifyAuthentication()
 *   3. The verified credential's userHandle is placed on the request as
 *      the 'webauthn.user_handle' attribute
 *   4. This guard resolves the user from that attribute via UserProviderInterface
 *
 * SECURITY:
 * - Does NOT perform WebAuthn cryptographic verification — it trusts the
 *   upstream middleware/controller that already verified the assertion.
 * - The 'webauthn.user_handle' attribute must only be set after a successful
 *   cryptographic verification to maintain security.
 *
 * @see https://github.com/MonkeysCloud/MonkeysLegion-WebAuthn
 */
final class WebAuthnGuard implements GuardInterface
{
    /** Request attribute key for the authenticated user handle. */
    public const string ATTRIBUTE_USER_HANDLE = 'webauthn.user_handle';

    /** Request attribute key for the credential ID (informational). */
    public const string ATTRIBUTE_CREDENTIAL  = 'webauthn.credential_id';

    private ?AuthenticatableInterface $_user = null;

    public function __construct(
        private readonly UserProviderInterface $users,
    ) {}

    public function name(): string
    {
        return 'webauthn';
    }

    /**
     * Authenticate from a pre-verified WebAuthn assertion.
     *
     * Expects the request to carry the ATTRIBUTE_USER_HANDLE attribute set
     * by the WebAuthn verification layer after a successful assertion check.
     */
    public function authenticate(ServerRequestInterface $request): ?AuthenticatableInterface
    {
        $userHandle = $request->getAttribute(self::ATTRIBUTE_USER_HANDLE);

        if ($userHandle === null || $userHandle === '') {
            return null;
        }

        $user = $this->users->findById($userHandle);

        if ($user !== null) {
            $this->_user = $user;
        }

        return $user;
    }

    /**
     * Validate credentials.
     *
     * Accepts a 'user_handle' key in $credentials and checks that the
     * corresponding user exists. Actual WebAuthn cryptographic validation
     * must be performed separately by WebAuthnService.
     *
     * @param array<string, mixed> $credentials
     */
    public function validate(array $credentials): bool
    {
        $userHandle = $credentials['user_handle'] ?? null;
        if ($userHandle === null || $userHandle === '') {
            return false;
        }

        return $this->users->findById($userHandle) !== null;
    }

    public function user(): ?AuthenticatableInterface
    {
        return $this->_user;
    }

    public function id(): int|string|null
    {
        return $this->_user?->getAuthIdentifier();
    }

    public function check(): bool
    {
        return $this->_user !== null;
    }

    public function guest(): bool
    {
        return $this->_user === null;
    }
}
