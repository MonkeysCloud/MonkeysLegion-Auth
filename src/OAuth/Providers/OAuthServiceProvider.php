<?php
declare(strict_types=1);

namespace MonkeysLegion\Auth\OAuth\Providers;

use MonkeysLegion\Auth\OAuth\{
    FacebookOAuthProvider,
    GitHubOAuthProvider,
    GitLabOAuthProvider,
    GoogleOAuthProvider,
    MicrosoftOAuthProvider,
    OAuthManager,
    XOAuthProvider,
};

/**
 * MonKeysLegion Framework — Auth Package
 *
 * Registers OAuth providers from configuration.
 *
 * @copyright 2026 MonKeysCloud Team
 * @license   MIT
 */
final class OAuthServiceProvider
{
    /**
     * Register OAuth providers based on config/services.mlc.
     *
     * @param array<string, array<string, mixed>> $config Provider configs.
     * @param callable(string, callable): void $register DI registration callback.
     */
    public function register(array $config, callable $register): void
    {
        $register(OAuthManager::class, function() use ($config): OAuthManager {
            $manager = new OAuthManager();

            foreach ($config as $name => $providerConfig) {
                if (!($providerConfig['client_id'] ?? '') || !($providerConfig['client_secret'] ?? '')) {
                    continue; // Skip unconfigured providers
                }

                $provider = $this->createProvider($name, $providerConfig);
                if ($provider !== null) {
                    $manager->register($name, $provider);
                }
            }

            return $manager;
        });
    }

    /**
     * @param array<string, mixed> $config
     */
    private function createProvider(string $name, array $config): ?object
    {
        $clientId = (string) $config['client_id'];
        $clientSecret = (string) $config['client_secret'];
        $redirectUri = (string) ($config['redirect_uri'] ?? '');
        $scopes = (array) ($config['scopes'] ?? []);

        return match ($name) {
            'google'    => new GoogleOAuthProvider($clientId, $clientSecret, $redirectUri, $scopes),
            'github'    => new GitHubOAuthProvider($clientId, $clientSecret, $redirectUri, $scopes),
            'gitlab'    => new GitLabOAuthProvider(
                $clientId, $clientSecret, $redirectUri, $scopes,
                $config['url'] ?? 'https://gitlab.com',
            ),
            'facebook'  => new FacebookOAuthProvider($clientId, $clientSecret, $redirectUri, $scopes),
            'x', 'twitter' => new XOAuthProvider($clientId, $clientSecret, $redirectUri, $scopes),
            'microsoft' => new MicrosoftOAuthProvider(
                $clientId, $clientSecret, $redirectUri, $scopes,
                $config['tenant'] ?? 'common',
            ),
            default => null,
        };
    }
}
