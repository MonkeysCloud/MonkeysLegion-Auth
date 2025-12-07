<?php

declare(strict_types=1);

namespace MonkeysLegion\Auth\OAuth;

use MonkeysLegion\Auth\Contract\OAuthProviderInterface;
use MonkeysLegion\Auth\Contract\UserProviderInterface;
use MonkeysLegion\Auth\Contract\EventDispatcherInterface;
use MonkeysLegion\Auth\Events\LoginSucceeded;
use MonkeysLegion\Auth\Events\UserRegistered;
use MonkeysLegion\Auth\JwtService;
use RuntimeException;
use PDO;

/**
 * Orchestrates OAuth authentication flows.
 * 
 * Required table:
 * 
 * CREATE TABLE oauth_accounts (
 *     id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
 *     user_id BIGINT UNSIGNED NOT NULL,
 *     provider VARCHAR(50) NOT NULL,
 *     provider_id VARCHAR(255) NOT NULL,
 *     access_token TEXT,
 *     refresh_token TEXT,
 *     token_expires_at INT UNSIGNED,
 *     created_at INT UNSIGNED NOT NULL,
 *     updated_at INT UNSIGNED NOT NULL,
 *     UNIQUE INDEX idx_provider_id (provider, provider_id),
 *     INDEX idx_user (user_id)
 * );
 */
final class OAuthService
{
    /** @var array<string, OAuthProviderInterface> */
    private array $providers = [];

    public function __construct(
        private readonly PDO $pdo,
        private readonly JwtService $jwt,
        private readonly ?UserProviderInterface $users = null,
        private readonly ?EventDispatcherInterface $events = null
    ) {}

    /**
     * Register an OAuth provider.
     */
    public function registerProvider(OAuthProviderInterface $provider): void
    {
        $this->providers[$provider->getName()] = $provider;
    }

    /**
     * Get a registered provider.
     */
    public function getProvider(string $name): OAuthProviderInterface
    {
        if (!isset($this->providers[$name])) {
            throw new RuntimeException("OAuth provider '{$name}' not registered");
        }

        return $this->providers[$name];
    }

    /**
     * Generate CSRF state token.
     */
    public function generateState(): string
    {
        return bin2hex(random_bytes(32));
    }

    /**
     * Handle OAuth callback and authenticate/register user.
     *
     * @param string $provider Provider name
     * @param string $code     Authorization code
     *
     * @return array{token: string, user_id: int, is_new: bool}
     */
    public function handleCallback(string $provider, string $code): array
    {
        $oauthProvider = $this->getProvider($provider);

        // Exchange code for token
        $tokens = $oauthProvider->getAccessToken($code);
        $userInfo = $oauthProvider->getUserInfo($tokens['access_token']);

        if (empty($userInfo['email'])) {
            throw new RuntimeException('Email not provided by OAuth provider');
        }

        // Check if OAuth account exists
        $existingAccount = $this->findOAuthAccount($provider, $userInfo['id']);

        if ($existingAccount !== null) {
            // Update tokens
            $this->updateOAuthTokens(
                $existingAccount['id'],
                $tokens['access_token'],
                $tokens['refresh_token'] ?? null,
                $tokens['expires_in']
            );

            $userId = (int) $existingAccount['user_id'];
            $isNew = false;
        } else {
            // Check if user exists with this email
            $user = $this->users?->findByEmail($userInfo['email']);

            if ($user !== null) {
                $userId = (int) $user->getAuthIdentifier();
            } else {
                // Create new user
                $userId = $this->createUserFromOAuth($userInfo);
                $isNew = true;
            }

            // Link OAuth account
            $this->linkOAuthAccount(
                $userId,
                $provider,
                $userInfo['id'],
                $tokens['access_token'],
                $tokens['refresh_token'] ?? null,
                $tokens['expires_in']
            );

            $isNew = $isNew ?? false;
        }

        // Issue JWT
        $token = $this->jwt->issue([
            'sub' => $userId,
            'oauth_provider' => $provider,
        ]);

        // Dispatch events
        if ($isNew ?? false) {
            $this->events?->dispatch(new UserRegistered($userId, $userInfo['email']));
        }
        $this->events?->dispatch(new LoginSucceeded($userId, $userInfo['email']));

        return [
            'token' => $token,
            'user_id' => $userId,
            'is_new' => $isNew ?? false,
        ];
    }

    /**
     * Unlink an OAuth provider from a user.
     */
    public function unlinkProvider(int $userId, string $provider): bool
    {
        $stmt = $this->pdo->prepare(
            'DELETE FROM oauth_accounts WHERE user_id = ? AND provider = ?'
        );
        $stmt->execute([$userId, $provider]);
        return $stmt->rowCount() > 0;
    }

    /**
     * Get all linked OAuth providers for a user.
     *
     * @return array<array{provider: string, provider_id: string, created_at: int}>
     */
    public function getLinkedProviders(int $userId): array
    {
        $stmt = $this->pdo->prepare(
            'SELECT provider, provider_id, created_at
             FROM oauth_accounts
             WHERE user_id = ?'
        );
        $stmt->execute([$userId]);

        $accounts = [];
        while ($row = $stmt->fetch(PDO::FETCH_ASSOC)) {
            $accounts[] = [
                'provider' => $row['provider'],
                'provider_id' => $row['provider_id'],
                'created_at' => (int) $row['created_at'],
            ];
        }

        return $accounts;
    }

    private function findOAuthAccount(string $provider, string $providerId): ?array
    {
        $stmt = $this->pdo->prepare(
            'SELECT id, user_id FROM oauth_accounts WHERE provider = ? AND provider_id = ?'
        );
        $stmt->execute([$provider, $providerId]);
        $row = $stmt->fetch(PDO::FETCH_ASSOC);
        return $row ?: null;
    }

    private function linkOAuthAccount(
        int $userId,
        string $provider,
        string $providerId,
        string $accessToken,
        ?string $refreshToken,
        int $expiresIn
    ): void {
        $now = time();
        $stmt = $this->pdo->prepare(
            'INSERT INTO oauth_accounts 
             (user_id, provider, provider_id, access_token, refresh_token, token_expires_at, created_at, updated_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?)'
        );
        $stmt->execute([
            $userId,
            $provider,
            $providerId,
            $accessToken,
            $refreshToken,
            $now + $expiresIn,
            $now,
            $now,
        ]);
    }

    private function updateOAuthTokens(
        int $accountId,
        string $accessToken,
        ?string $refreshToken,
        int $expiresIn
    ): void {
        $sql = 'UPDATE oauth_accounts SET access_token = ?, token_expires_at = ?, updated_at = ?';
        $params = [$accessToken, time() + $expiresIn, time()];

        if ($refreshToken !== null) {
            $sql .= ', refresh_token = ?';
            $params[] = $refreshToken;
        }

        $sql .= ' WHERE id = ?';
        $params[] = $accountId;

        $stmt = $this->pdo->prepare($sql);
        $stmt->execute($params);
    }

    private function createUserFromOAuth(array $userInfo): int
    {
        // This should be handled by your actual User creation logic
        // For now, throw an exception - implement based on your User entity
        throw new RuntimeException(
            'User creation from OAuth not implemented. Extend OAuthService or provide UserProviderInterface.'
        );
    }
}
