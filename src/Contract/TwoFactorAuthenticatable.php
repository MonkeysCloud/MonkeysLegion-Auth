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
 * Contract for entities that support two-factor authentication.
 */
interface TwoFactorAuthenticatable
{
    public function hasTwoFactorEnabled(): bool;

    public function getTwoFactorSecret(): ?string;

    /**
     * @return list<string> Hashed recovery codes.
     */
    public function getRecoveryCodes(): array;

    /**
     * @param list<string> $codes Hashed recovery codes.
     */
    public function setRecoveryCodes(array $codes): void;
}
