<?php
declare(strict_types=1);

namespace MonkeysLegion\Auth\OAuth;

use MonkeysLegion\Auth\DTO\OAuthUser;

/**
 * GitLab OAuth 2.0 provider.
 *
 * @copyright 2026 MonkeysCloud Team
 * @license   MIT
 */
final class GitLabOAuthProvider extends AbstractOAuthProvider
{
    public function __construct(
        string $clientId,
        string $clientSecret,
        string $redirectUri,
        array $scopes = [],
        private readonly string $gitlabUrl = 'https://gitlab.com',
    ) {
        parent::__construct($clientId, $clientSecret, $redirectUri, $scopes);
    }

    protected function getAuthUrl(): string
    {
        return $this->gitlabUrl . '/oauth/authorize';
    }

    protected function getTokenUrl(): string
    {
        return $this->gitlabUrl . '/oauth/token';
    }

    protected function getUserUrl(): string
    {
        return $this->gitlabUrl . '/api/v4/user';
    }

    public function getName(): string
    {
        return 'gitlab';
    }

    protected function mapToUser(array $userInfo): OAuthUser
    {
        return new OAuthUser(
            providerId: (string) ($userInfo['id'] ?? ''),
            provider: $this->getName(),
            email: $userInfo['email'] ?? null,
            name: $userInfo['name'] ?? null,
            avatar: $userInfo['avatar_url'] ?? null,
            nickname: $userInfo['username'] ?? null,
            raw: $userInfo,
        );
    }
}
