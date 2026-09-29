<?php
declare(strict_types=1);

namespace MonkeysLegion\Auth\OAuth;

use MonkeysLegion\Auth\DTO\OAuthUser;

/**
 * X (Twitter) OAuth 2.0 provider.
 *
 * Uses OAuth 2.0 PKCE flow (not OAuth 1.0a).
 *
 * @copyright 2026 MonKeysCloud Team
 * @license   MIT
 */
final class XOAuthProvider extends AbstractOAuthProvider
{
    protected function getAuthUrl(): string
    {
        return 'https://twitter.com/i/oauth2/authorize';
    }

    protected function getTokenUrl(): string
    {
        return 'https://api.twitter.com/2/oauth2/token';
    }

    protected function getUserUrl(): string
    {
        return 'https://api.twitter.com/2/users/me?user.fields=id,name,username,email,profile_image_url';
    }

    public function getName(): string
    {
        return 'x';
    }

    protected function mapToUser(array $userInfo): OAuthUser
    {
        $user = $userInfo['data'] ?? $userInfo;

        return new OAuthUser(
            providerId: (string) ($user['id'] ?? ''),
            provider: $this->getName(),
            email: $user['email'] ?? null,
            name: $user['name'] ?? null,
            avatar: $user['profile_image_url'] ?? null,
            nickname: $user['username'] ?? null,
            raw: $userInfo,
        );
    }
}
