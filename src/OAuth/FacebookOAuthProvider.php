<?php
declare(strict_types=1);

namespace MonkeysLegion\Auth\OAuth;

use MonkeysLegion\Auth\DTO\OAuthUser;

/**
 * Facebook OAuth 2.0 provider.
 *
 * @copyright 2026 MonKeysCloud Team
 * @license   MIT
 */
final class FacebookOAuthProvider extends AbstractOAuthProvider
{
    protected function getAuthUrl(): string
    {
        return 'https://www.facebook.com/v19.0/dialog/oauth';
    }

    protected function getTokenUrl(): string
    {
        return 'https://graph.facebook.com/v19.0/oauth/access_token';
    }

    protected function getUserUrl(): string
    {
        return 'https://graph.facebook.com/v19.0/me?fields=id,name,email,picture';
    }

    public function getName(): string
    {
        return 'facebook';
    }

    protected function mapToUser(array $userInfo): OAuthUser
    {
        $avatar = null;
        if (isset($userInfo['picture']['data']['url'])) {
            $avatar = $userInfo['picture']['data']['url'];
        }

        return new OAuthUser(
            providerId: (string) ($userInfo['id'] ?? ''),
            provider: $this->getName(),
            email: $userInfo['email'] ?? null,
            name: $userInfo['name'] ?? null,
            avatar: $avatar,
            nickname: null,
            raw: $userInfo,
        );
    }
}
