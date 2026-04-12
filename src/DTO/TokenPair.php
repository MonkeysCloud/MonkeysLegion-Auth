<?php

declare(strict_types=1);

namespace MonkeysLegion\Auth\DTO;

/**
 * Token pair — access + refresh tokens.
 *
 * Uses PHP 8.4 property hooks for computed properties.
 */
final readonly class TokenPair
{
    public function __construct(
        public string $accessToken,
        public string $refreshToken,
        public int $accessExpiresAt,
        public int $refreshExpiresAt,
        public ?string $familyId = null,
    ) {}

    /**
     * Check if the access token has expired.
     */
    public function isAccessExpired(): bool
    {
        return time() >= $this->accessExpiresAt;
    }

    /**
     * Seconds until access token expires.
     */
    public function accessExpiresIn(): int
    {
        return max(0, $this->accessExpiresAt - time());
    }

    /**
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return [
            'access_token'      => $this->accessToken,
            'refresh_token'     => $this->refreshToken,
            'token_type'        => 'Bearer',
            'expires_in'        => $this->accessExpiresIn(),
            'expires_at'        => $this->accessExpiresAt,
            'refresh_expires_at' => $this->refreshExpiresAt,
        ];
    }
}
