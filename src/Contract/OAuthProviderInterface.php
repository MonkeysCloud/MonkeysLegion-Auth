<?php

declare(strict_types=1);

namespace MonkeysLegion\Auth\Contract;

use MonkeysLegion\Auth\DTO\OAuthUser;

/**
 * Contract for OAuth2 providers.
 */
interface OAuthProviderInterface
{
    /**
     * Get the provider name (e.g., 'google', 'github').
     */
    public function getName(): string;

    /**
     * Generate the authorization URL.
     *
     * @param string[] $scopes
     */
    public function getAuthorizationUrl(string $state, array $scopes = []): string;

    /**
     * Exchange authorization code for access token.
     *
     * @return array{access_token: string, refresh_token?: string, expires_in?: int}
     */
    public function getAccessToken(string $code): array;

    /**
     * Get user info from the provider.
     */
    public function getUser(string $accessToken): OAuthUser;

    /**
     * Refresh an access token.
     *
     * @return array{access_token: string, refresh_token?: string, expires_in?: int}
     */
    public function refreshToken(string $refreshToken): array;
}
