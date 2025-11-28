<?php

declare(strict_types=1);

namespace MonkeysLegion\Auth\ApiKey;

use MonkeysLegion\Auth\Exception\InvalidApiKeyException;

/**
 * API Key generation and validation service.
 */
final class ApiKeyService
{
    private const PREFIX_LENGTH = 8;
    private const KEY_LENGTH = 32;

    public function __construct(
        private ApiKeyRepositoryInterface $repository,
        private string $prefix = 'ml_',
    ) {}

    /**
     * Generate a new API key.
     *
     * @return array{key: string, hash: string, prefix: string}
     */
    public function generate(): array
    {
        // Generate the visible prefix (for identification)
        $visiblePrefix = $this->prefix . bin2hex(random_bytes(self::PREFIX_LENGTH / 2));

        // Generate the secret part
        $secret = bin2hex(random_bytes(self::KEY_LENGTH));

        // Full key = prefix + underscore + secret
        $fullKey = $visiblePrefix . '_' . $secret;

        // Store only the hash of the full key
        $hash = hash('sha256', $fullKey);

        return [
            'key' => $fullKey,        // Return to user once, never stored
            'hash' => $hash,           // Store this
            'prefix' => $visiblePrefix, // Store for display/identification
        ];
    }

    /**
     * Create a new API key for a user.
     *
     * @return array{id: int|string, key: string, prefix: string}
     */
    public function create(
        int|string $userId,
        string $name,
        ?array $scopes = null,
        ?\DateTimeInterface $expiresAt = null,
    ): array {
        $generated = $this->generate();

        $id = $this->repository->create([
            'user_id' => $userId,
            'name' => $name,
            'prefix' => $generated['prefix'],
            'hash' => $generated['hash'],
            'scopes' => $scopes,
            'expires_at' => $expiresAt,
            'last_used_at' => null,
        ]);

        return [
            'id' => $id,
            'key' => $generated['key'],
            'prefix' => $generated['prefix'],
        ];
    }

    /**
     * Validate an API key.
     *
     * @throws InvalidApiKeyException
     * @return array The API key record
     */
    public function validate(string $key): array
    {
        // Extract prefix for lookup
        $parts = explode('_', $key);
        if (count($parts) < 3) {
            throw new InvalidApiKeyException('Invalid API key format');
        }

        $prefix = $parts[0] . '_' . $parts[1];
        $hash = hash('sha256', $key);

        // Find by prefix first (fast lookup)
        $record = $this->repository->findByPrefix($prefix);

        if (!$record) {
            throw new InvalidApiKeyException('API key not found');
        }

        // Verify hash
        if (!hash_equals($record['hash'], $hash)) {
            throw new InvalidApiKeyException('Invalid API key');
        }

        // Check if revoked
        if (!empty($record['revoked_at'])) {
            throw new InvalidApiKeyException('API key has been revoked');
        }

        // Check expiration
        if (!empty($record['expires_at'])) {
            $expiresAt = $record['expires_at'] instanceof \DateTimeInterface
                ? $record['expires_at']->getTimestamp()
                : strtotime($record['expires_at']);

            if (time() > $expiresAt) {
                throw new InvalidApiKeyException('API key has expired');
            }
        }

        // Update last used
        $this->repository->updateLastUsed($record['id']);

        return $record;
    }

    /**
     * Check if a key has a specific scope.
     */
    public function hasScope(array $keyRecord, string $scope): bool
    {
        $scopes = $keyRecord['scopes'] ?? null;

        // null = all scopes allowed
        if ($scopes === null) {
            return true;
        }

        // Wildcard
        if (in_array('*', $scopes, true)) {
            return true;
        }

        // Exact match
        if (in_array($scope, $scopes, true)) {
            return true;
        }

        // Prefix match (e.g., "read:*" matches "read:users")
        foreach ($scopes as $s) {
            if (str_ends_with($s, ':*')) {
                $prefix = substr($s, 0, -1);
                if (str_starts_with($scope, $prefix)) {
                    return true;
                }
            }
        }

        return false;
    }

    /**
     * Revoke an API key.
     */
    public function revoke(int|string $keyId): void
    {
        $this->repository->revoke($keyId);
    }

    /**
     * Revoke all API keys for a user.
     */
    public function revokeAllForUser(int|string $userId): void
    {
        $this->repository->revokeAllForUser($userId);
    }

    /**
     * List all API keys for a user (without the actual keys).
     */
    public function listForUser(int|string $userId): array
    {
        return $this->repository->findByUserId($userId);
    }
}
