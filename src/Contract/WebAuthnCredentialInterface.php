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
 * Optional contract for querying WebAuthn credential metadata from the Auth layer.
 *
 * Implement this interface on your UserProviderInterface implementation (or on a
 * dedicated repository) when you want the Auth layer to inspect passkey state
 * without directly depending on MonkeysLegion\WebAuthn internals.
 *
 * @see https://github.com/MonkeysCloud/MonkeysLegion-WebAuthn
 */
interface WebAuthnCredentialInterface
{
    /**
     * Return the base64url-encoded credential IDs registered for a user.
     *
     * @return list<string>
     */
    public function getPasskeyCredentialIds(int|string $userId): array;

    /**
     * Return true when the user has at least one registered passkey.
     */
    public function hasPasskeys(int|string $userId): bool;

    /**
     * Return the WebAuthn user-handle for the given user (typically the user ID).
     * Must be stable across registrations for the same account.
     */
    public function getUserHandle(int|string $userId): string;
}
