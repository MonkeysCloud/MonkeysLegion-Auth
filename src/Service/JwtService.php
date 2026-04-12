<?php

declare(strict_types=1);

/**
 * MonkeysLegion Auth v2
 *
 * @package   MonkeysLegion\Auth
 * @author    MonkeysCloud <jorge@monkeys.cloud>
 * @license   MIT
 *
 * @requires  PHP 8.4
 */

namespace MonkeysLegion\Auth\Service;

use Firebase\JWT\ExpiredException;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use MonkeysLegion\Auth\Exception\TokenExpiredException;
use MonkeysLegion\Auth\Exception\TokenInvalidException;

/**
 * JWT token issuance and verification.
 *
 * SECURITY: Supports HS256 (symmetric) and RS256 (asymmetric).
 * Token IDs use CSPRNG for unpredictability.
 *
 * PERFORMANCE: Static Key object reused per instance.
 *
 * Uses PHP 8.4: property hooks.
 */
final class JwtService
{
    private Key $key;

    // ── Property Hooks ─────────────────────────────────────────

    /** Access token TTL in seconds. */
    public int $accessTtl {
        get => $this->_accessTtl;
    }
    private int $_accessTtl;

    /** Refresh token TTL in seconds. */
    public int $refreshTtl {
        get => $this->_refreshTtl;
    }
    private int $_refreshTtl;

    public function __construct(
        private readonly string $secret,
        int $accessTtl = 1800,      // 30 minutes
        int $refreshTtl = 604800,   // 7 days
        private readonly int $leeway = 0,
        private readonly int $nbfSkew = 0,
        private readonly ?string $issuer = null,
        private readonly ?string $audience = null,
        private readonly string $algorithm = 'HS256',
    ) {
        $this->_accessTtl  = $accessTtl;
        $this->_refreshTtl = $refreshTtl;
        $this->key         = new Key($this->secret, $this->algorithm);
    }

    // ── Token Issuance ─────────────────────────────────────────

    /**
     * Issue an access token.
     *
     * @param array<string, mixed> $claims
     */
    public function issueAccessToken(array $claims): string
    {
        $claims['jti'] ??= $this->generateTokenId();
        return $this->issue($claims, $this->_accessTtl);
    }

    /**
     * Issue a refresh token with a unique family ID.
     *
     * SECURITY: Token family tracking detects refresh token reuse attacks.
     *
     * @param array<string, mixed> $claims
     */
    public function issueRefreshToken(array $claims, ?string $familyId = null): string
    {
        $claims['jti']    ??= $this->generateTokenId();
        $claims['type']     = 'refresh';
        $claims['family'] ??= $familyId ?? $this->generateTokenId();
        return $this->issue($claims, $this->_refreshTtl);
    }

    /**
     * Issue a token with custom TTL.
     *
     * @param array<string, mixed> $claims
     */
    public function issue(array $claims, int $ttl): string
    {
        $now = time();

        $payload = array_merge([
            'iat' => $now,
            'nbf' => $now - $this->nbfSkew,
            'exp' => $now + $ttl,
        ], $claims);

        if ($this->issuer !== null) {
            $payload['iss'] = $this->issuer;
        }

        if ($this->audience !== null) {
            $payload['aud'] = $this->audience;
        }

        return JWT::encode($payload, $this->secret, $this->algorithm);
    }

    // ── Token Verification ─────────────────────────────────────

    /**
     * Decode and verify a token.
     *
     * SECURITY: Always validates signature, expiry, and nbf.
     *
     * @return array<string, mixed>
     * @throws TokenExpiredException
     * @throws TokenInvalidException
     */
    public function decode(string $token): array
    {
        return $this->decodeInternal($token, $this->leeway);
    }

    /**
     * Decode with extra leeway — for refresh/revocation operations.
     *
     * @return array<string, mixed>
     * @throws TokenExpiredException
     * @throws TokenInvalidException
     */
    public function decodeWithLeeway(string $token, int $extraLeeway): array
    {
        return $this->decodeInternal($token, max($this->leeway, $extraLeeway));
    }

    // ── Token Introspection ────────────────────────────────────

    /**
     * Internal decode implementation — saves/restores JWT::$leeway around
     * the call to avoid mutating the global state for concurrent requests.
     *
     * @return array<string, mixed>
     * @throws TokenExpiredException
     * @throws TokenInvalidException
     */
    private function decodeInternal(string $token, int $leeway): array
    {
        $originalLeeway = JWT::$leeway;
        JWT::$leeway    = $leeway;

        try {
            $payload = JWT::decode($token, $this->key);
            return $this->objectToArray($payload);
        } catch (ExpiredException $e) {
            throw new TokenExpiredException('Token has expired.', [
                'expired_at' => $e->getPayload()?->exp ?? null,
            ]);
        } catch (\Throwable $e) {
            throw new TokenInvalidException('Invalid token.', [
                'reason' => $e->getMessage(),
            ]);
        } finally {
            JWT::$leeway = $originalLeeway;
        }
    }

    /**
     * Get token expiration without full verification.
     *
     * SECURITY: Does NOT verify signature — use for informational purposes only.
     */
    public function getExpiration(string $token): ?int
    {
        $parts = explode('.', $token);
        if (count($parts) !== 3) {
            return null;
        }

        try {
            $payload = json_decode(
                base64_decode(strtr($parts[1], '-_', '+/')),
                true,
                512,
                JSON_THROW_ON_ERROR,
            );
            return $payload['exp'] ?? null;
        } catch (\Throwable) {
            return null;
        }
    }

    /**
     * Check if a token is expired (without signature verification).
     */
    public function isExpired(string $token): bool
    {
        $exp = $this->getExpiration($token);
        return $exp === null || time() > $exp;
    }

    /**
     * Extract the token ID (jti) claim.
     */
    public function getTokenId(string $token): ?string
    {
        try {
            $claims = $this->decodeWithLeeway($token, 86400 * 30);
            return $claims['jti'] ?? null;
        } catch (\Throwable) {
            return null;
        }
    }

    /**
     * Generate a cryptographically secure token ID.
     *
     * SECURITY: Uses CSPRNG via random_bytes().
     */
    public function generateTokenId(): string
    {
        return bin2hex(random_bytes(16));
    }

    /**
     * @return array<string, mixed>
     */
    private function objectToArray(object $obj): array
    {
        return json_decode(
            json_encode($obj),
            true,
            512,
            JSON_THROW_ON_ERROR,
        );
    }
}
