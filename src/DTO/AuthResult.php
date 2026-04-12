<?php

declare(strict_types=1);

/**
 * MonkeysLegion Auth v2
 *
 * @package   MonkeysLegion\Auth
 * @author    MonkeysCloud <jorge@monkeyscloud.com>
 * @license   MIT
 *
 * @requires  PHP 8.4
 */

namespace MonkeysLegion\Auth\DTO;

use MonkeysLegion\Auth\Contract\AuthenticatableInterface;

/**
 * Authentication result — immutable response from auth operations.
 */
final readonly class AuthResult
{
    public function __construct(
        public bool $success,
        public ?AuthenticatableInterface $user = null,
        public ?TokenPair $tokens = null,
        public bool $requires2FA = false,
        public ?string $challengeToken = null,
        public ?string $guard = null,
        public ?string $error = null,
    ) {}

    public static function success(
        AuthenticatableInterface $user,
        TokenPair $tokens,
        ?string $guard = null,
    ): self {
        return new self(
            success: true,
            user: $user,
            tokens: $tokens,
            guard: $guard,
        );
    }

    public static function requires2FA(string $challengeToken): self
    {
        return new self(
            success: false,
            requires2FA: true,
            challengeToken: $challengeToken,
        );
    }

    public static function failure(string $error): self
    {
        return new self(
            success: false,
            error: $error,
        );
    }

    /**
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        $data = ['success' => $this->success];

        if ($this->tokens !== null) {
            $data['tokens'] = $this->tokens->toArray();
        }

        if ($this->requires2FA) {
            $data['requires_2fa']    = true;
            $data['challenge_token'] = $this->challengeToken;
        }

        if ($this->guard !== null) {
            $data['guard'] = $this->guard;
        }

        if ($this->error !== null) {
            $data['error'] = $this->error;
        }

        return $data;
    }
}
