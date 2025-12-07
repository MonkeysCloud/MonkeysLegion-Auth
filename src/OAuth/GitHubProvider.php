<?php

declare(strict_types=1);

namespace MonkeysLegion\Auth\OAuth;

/**
 * GitHub OAuth provider.
 */
final class GitHubProvider extends AbstractOAuthProvider
{
    public function getName(): string
    {
        return 'github';
    }

    protected function getAuthorizationEndpoint(): string
    {
        return 'https://github.com/login/oauth/authorize';
    }

    protected function getTokenEndpoint(): string
    {
        return 'https://github.com/login/oauth/access_token';
    }

    protected function getUserInfoEndpoint(): string
    {
        return 'https://api.github.com/user';
    }

    protected function getDefaultScopes(): array
    {
        return ['user:email'];
    }

    protected function parseUserInfo(array $data): array
    {
        return [
            'id' => (string) $data['id'],
            'email' => $data['email'],
            'name' => $data['name'] ?? $data['login'] ?? null,
            'avatar' => $data['avatar_url'] ?? null,
            'login' => $data['login'] ?? null,
        ];
    }

    public function getUserInfo(string $accessToken): array
    {
        $user = parent::getUserInfo($accessToken);

        // GitHub may not return email if it's private, fetch separately
        if (empty($user['email'])) {
            $emails = $this->httpGet(
                'https://api.github.com/user/emails',
                ['Authorization' => 'Bearer ' . $accessToken]
            );

            foreach ($emails as $email) {
                if ($email['primary'] && $email['verified']) {
                    $user['email'] = $email['email'];
                    break;
                }
            }
        }

        return $user;
    }
}
