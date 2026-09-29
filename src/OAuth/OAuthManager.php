<?php
declare(strict_types=1);

namespace MonkeysLegion\Auth\OAuth;

use MonkeysLegion\Auth\Contract\OAuthProviderInterface;
use MonkeysLegion\Auth\DTO\OAuthUser;

/**
 * MonKeysLegion Framework — Auth Package
 *
 * Manager for OAuth providers.
 *
 * Usage:
 *   $url = OAuth::provider('github')->getAuthorizationUrl($state);
 *   $user = OAuth::provider('github')->getUser($accessToken);
 *
 * @copyright 2026 MonKeysCloud Team
 * @license   MIT
 */
final class OAuthManager
{
    /** @var array<string, OAuthProviderInterface> */
    private array $providers = [];

    /**
     * Register an OAuth provider.
     */
    public function register(string $name, OAuthProviderInterface $provider): void
    {
        $this->providers[$name] = $provider;
    }

    /**
     * Check if a provider is registered.
     */
    public function has(string $name): bool
    {
        return isset($this->providers[$name]);
    }

    /**
     * Get a registered provider.
     *
     * @throws \RuntimeException If provider not found.
     */
    public function provider(string $name): OAuthProviderInterface
    {
        if (!$this->has($name)) {
            throw new \RuntimeException("OAuth provider '{$name}' is not registered.");
        }
        return $this->providers[$name];
    }

    /**
     * Get all registered provider names.
     *
     * @return list<string>
     */
    public function availableProviders(): array
    {
        return array_keys($this->providers);
    }

    /**
     * Generate a random state token for CSRF protection.
     */
    public function generateState(): string
    {
        return AbstractOAuthProvider::generateState();
    }
}
