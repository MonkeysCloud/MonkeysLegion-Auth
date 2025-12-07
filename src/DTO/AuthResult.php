<?php

declare(strict_types=1);

namespace MonkeysLegion\Auth\DTO;

use MonkeysLegion\Auth\Contract\AuthenticatableInterface;

/**
 * Data transfer object for authentication results.
 */
final readonly class AuthResult
{
    public function __construct(
        public bool $success,
        public ?AuthenticatableInterface $user = null,
        public ?TokenPair $tokens = null,
        public bool $requires2FA = false,
        public ?string $challengeToken = null,
        public ?string $error = null,
    ) {}

    public static function success(AuthenticatableInterface $user, TokenPair $tokens): self
    {
        return new self(
            success: true,
            user: $user,
            tokens: $tokens,
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

    public function toArray(): array
    {
        $data = ['success' => $this->success];

        if ($this->tokens) {
            $data['tokens'] = $this->tokens->toArray();
        }

        if ($this->requires2FA) {
            $data['requires_2fa'] = true;
            $data['challenge_token'] = $this->challengeToken;
        }

        if ($this->error) {
            $data['error'] = $this->error;
        }

        return $data;
    }
}
