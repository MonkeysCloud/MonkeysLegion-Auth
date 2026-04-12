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

namespace MonkeysLegion\Auth\DTO;

/**
 * Password policy configuration.
 *
 * SECURITY: Based on NIST SP 800-63B guidelines.
 */
final readonly class PasswordPolicy
{
    public function __construct(
        public int $minLength = 8,
        public int $maxLength = 128,
        public bool $requireUppercase = false,
        public bool $requireLowercase = false,
        public bool $requireNumbers = false,
        public bool $requireSymbols = false,
        public bool $rejectCommon = true,
        /** @var list<string> Custom common passwords to reject */
        public array $commonPasswords = [],
    ) {}

    /**
     * Validate a password against the policy.
     *
     * @return list<string> Validation errors (empty = valid).
     */
    public function validate(string $password): array
    {
        $errors = [];
        $len    = mb_strlen($password);

        if ($len < $this->minLength) {
            $errors[] = "Password must be at least {$this->minLength} characters.";
        }

        if ($len > $this->maxLength) {
            $errors[] = "Password must not exceed {$this->maxLength} characters.";
        }

        if ($this->requireUppercase && !preg_match('/[A-Z]/', $password)) {
            $errors[] = 'Password must contain at least one uppercase letter.';
        }

        if ($this->requireLowercase && !preg_match('/[a-z]/', $password)) {
            $errors[] = 'Password must contain at least one lowercase letter.';
        }

        if ($this->requireNumbers && !preg_match('/[0-9]/', $password)) {
            $errors[] = 'Password must contain at least one number.';
        }

        if ($this->requireSymbols && !preg_match('/[^a-zA-Z0-9]/', $password)) {
            $errors[] = 'Password must contain at least one special character.';
        }

        if ($this->rejectCommon && $this->isCommon($password)) {
            $errors[] = 'Password is too common.';
        }

        return $errors;
    }

    /**
     * Check against a built-in list of common passwords.
     */
    private function isCommon(string $password): bool
    {
        static $common = [
            'password', '123456', '12345678', 'qwerty', 'abc123',
            'monkey', 'master', 'dragon', 'login', 'letmein',
            'welcome', 'admin', 'passw0rd', 'iloveyou', 'trustno1',
            'sunshine', 'princess', 'football', 'shadow', 'superman',
            'michael', 'password1', '123456789', '1234567890', 'qwerty123',
        ];

        $lower = strtolower($password);

        return in_array($lower, $common, true)
            || in_array($lower, $this->commonPasswords, true);
    }
}
