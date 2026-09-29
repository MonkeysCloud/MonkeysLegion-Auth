<?php
declare(strict_types=1);

namespace MonkeysLegion\Auth\OAuth;

use MonkeysLegion\Auth\DTO\OAuthUser;

/**
 * GitHub OAuth 2.0 provider.
 *
 * @copyright 2026 MonKeysCloud Team
 * @license   MIT
 */
final class GitHubOAuthProvider extends AbstractOAuthProvider
{
    protected function getAuthUrl(): string
    {
        return 'https://github.com/login/oauth/authorize';
    }

    protected function getTokenUrl(): string
    {
        return 'https://github.com/login/oauth/access_token';
    }

    protected function getUserUrl(): string
    {
        return 'https://api.github.com/user';
    }

    public function getName(): string
    {
        return 'github';
    }

    public function getUserInfo(string $accessToken): array
    {
        $user = parent::getUserInfo($accessToken);

        // Fetch primary email if not included
        if (!isset($user['email'])) {
            $emails = json_decode(
                $this->httpGet('https://api.github.com/user/emails', [
                    'Authorization: Bearer ' . $accessToken,
                    'Accept: application/json',
                ]),
                true,
            );

            if (is_array($emails)) {
                foreach ($emails as $email) {
                    if (($email['primary'] ?? false) === true) {
                        $user['email'] = $email['email'];
                        break;
                    }
                }
            }
        }

        return $user;
    }

    protected function mapToUser(array $userInfo): OAuthUser
    {
        return new OAuthUser(
            providerId: (string) ($userInfo['id'] ?? ''),
            provider: $this->getName(),
            email: $userInfo['email'] ?? null,
            name: $userInfo['name'] ?? null,
            avatar: $userInfo['avatar_url'] ?? null,
            nickname: $userInfo['login'] ?? null,
            raw: $userInfo,
        );
    }
}
