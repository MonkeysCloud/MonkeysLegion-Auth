<?php

declare(strict_types=1);

namespace MonkeysLegion\Auth\DTO;

/**
 * Data transfer object for token pairs.
 */
final readonly class TokenPair
{
    public function __construct(
        public string $accessToken,
        public ?string $refreshToken = null,
        public int $accessExpiresAt = 0,
        public int $refreshExpiresAt = 0,
        public string $tokenType = 'Bearer',
    ) {}

    public function toArray(): array
    {
        return [
            'access_token' => $this->accessToken,
            'refresh_token' => $this->refreshToken,
            'expires_in' => max(0, $this->accessExpiresAt - time()),
            'token_type' => $this->tokenType,
        ];
    }

    public function isAccessExpired(): bool
    {
        return $this->accessExpiresAt > 0 && time() >= $this->accessExpiresAt;
    }

    public function isRefreshExpired(): bool
    {
        return $this->refreshExpiresAt > 0 && time() >= $this->refreshExpiresAt;
    }
}
