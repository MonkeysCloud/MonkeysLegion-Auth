<?php
declare(strict_types=1);

namespace MonkeysLegion\Auth\OAuth;

use MonkeysLegion\Auth\DTO\OAuthUser;

/**
 * Google OAuth 2.0 provider.
 *
 * @copyright 2026 MonKeysCloud Team
 * @license   MIT
 */
final class GoogleOAuthProvider extends AbstractOAuthProvider
{
    protected function getAuthUrl(): string
    {
        return 'https://accounts.google.com/o/oauth2/v2/auth';
    }

    protected function getTokenUrl(): string
    {
        return 'https://oauth2.googleapis.com/token';
    }

    protected function getUserUrl(): string
    {
        return 'https://www.googleapis.com/oauth2/v3/userinfo';
    }

    public function getName(): string
    {
        return 'google';
    }

    protected function mapToUser(array $userInfo): OAuthUser
    {
        return new OAuthUser(
            providerId: (string) ($userInfo['sub'] ?? ''),
            provider: $this->getName(),
            email: $userInfo['email'] ?? null,
            name: $userInfo['name'] ?? null,
            avatar: $userInfo['picture'] ?? null,
            nickname: null,
            raw: $userInfo,
        );
    }
}
