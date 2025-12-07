<?php

declare(strict_types=1);

namespace MonkeysLegion\Auth\OAuth;

/**
 * Google OAuth2 provider.
 */
final class GoogleProvider extends AbstractOAuthProvider
{
    public function getName(): string
    {
        return 'google';
    }

    protected function getAuthorizationEndpoint(): string
    {
        return 'https://accounts.google.com/o/oauth2/v2/auth';
    }

    protected function getTokenEndpoint(): string
    {
        return 'https://oauth2.googleapis.com/token';
    }

    protected function getUserInfoEndpoint(): string
    {
        return 'https://www.googleapis.com/oauth2/v2/userinfo';
    }

    protected function getDefaultScopes(): array
    {
        return [
            'openid',
            'email',
            'profile',
        ];
    }

    protected function parseUserInfo(array $data): array
    {
        return [
            'id' => $data['id'],
            'email' => $data['email'],
            'name' => $data['name'] ?? null,
            'avatar' => $data['picture'] ?? null,
            'verified_email' => $data['verified_email'] ?? false,
        ];
    }
}
