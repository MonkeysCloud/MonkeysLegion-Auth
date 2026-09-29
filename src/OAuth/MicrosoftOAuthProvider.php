<?php
declare(strict_types=1);

namespace MonkeysLegion\Auth\OAuth;

use MonkeysLegion\Auth\DTO\OAuthUser;

/**
 * Microsoft (Azure AD / Microsoft Entra ID) OAuth 2.0 provider.
 *
 * @copyright 2026 MonKeysCloud Team
 * @license   MIT
 */
final class MicrosoftOAuthProvider extends AbstractOAuthProvider
{
    public function __construct(
        string $clientId,
        string $clientSecret,
        string $redirectUri,
        array $scopes = [],
        private readonly string $tenant = 'common',
    ) {
        parent::__construct($clientId, $clientSecret, $redirectUri, $scopes);
    }

    protected function getAuthUrl(): string
    {
        return "https://login.microsoftonline.com/{$this->tenant}/oauth2/v2.0/authorize";
    }

    protected function getTokenUrl(): string
    {
        return "https://login.microsoftonline.com/{$this->tenant}/oauth2/v2.0/token";
    }

    protected function getUserUrl(): string
    {
        return 'https://graph.microsoft.com/v1.0/me';
    }

    public function getName(): string
    {
        return 'microsoft';
    }

    protected function mapToUser(array $userInfo): OAuthUser
    {
        return new OAuthUser(
            providerId: (string) ($userInfo['id'] ?? ''),
            provider: $this->getName(),
            email: $userInfo['mail'] ?? $userInfo['userPrincipalName'] ?? null,
            name: $userInfo['displayName'] ?? null,
            avatar: null, // Microsoft Graph requires a separate API call for photo
            nickname: null,
            raw: $userInfo,
        );
    }
}
