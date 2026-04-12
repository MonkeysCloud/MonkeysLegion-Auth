<?php

declare(strict_types=1);

namespace MonkeysLegion\Auth\Contract;

/**
 * Contract for OAuth providers.
 */
interface OAuthProviderInterface
{
    public function getName(): string;

    /**
     * @param list<string> $scopes
     */
    public function getAuthorizationUrl(string $state, array $scopes = []): string;

    /**
     * @return array{access_token: string, refresh_token: ?string, expires_in: int}
     */
    public function getAccessToken(string $code): array;

    /**
     * @return array<string, mixed>
     */
    public function getUserInfo(string $accessToken): array;

    /**
     * @return array{access_token: string, refresh_token: ?string, expires_in: int}
     */
    public function refreshToken(string $refreshToken): array;
}
