<?php

declare(strict_types=1);

namespace MonkeysLegion\Auth\Service;

use Firebase\JWT\ExpiredException;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use MonkeysLegion\Auth\Exception\TokenExpiredException;
use MonkeysLegion\Auth\Exception\TokenInvalidException;

/**
 * Service for issuing and verifying JSON Web Tokens (JWT).
 */
final class JwtService
{
    private string $algorithm = 'HS256';

    public function __construct(
        private string $secret,
        private int $accessTtl = 1800,      // 30 minutes
        private int $refreshTtl = 604800,   // 7 days
        private int $leeway = 0,
        private int $nbfSkew = 0,
        private ?string $issuer = null,
        private ?string $audience = null,
    ) {}

    /**
     * Issue an access token.
     *
     * @param array<string, mixed> $claims
     */
    public function issueAccessToken(array $claims): string
    {
        $claims['jti'] = $claims['jti'] ?? $this->generateTokenId();
        return $this->issue($claims, $this->accessTtl);
    }

    /**
     * Issue a refresh token with a unique token ID.
     *
     * @param array<string, mixed> $claims
     */
    public function issueRefreshToken(array $claims): string
    {
        $claims['jti'] = $claims['jti'] ?? $this->generateTokenId();
        $claims['type'] = 'refresh';
        return $this->issue($claims, $this->refreshTtl);
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

        if ($this->issuer) {
            $payload['iss'] = $this->issuer;
        }

        if ($this->audience) {
            $payload['aud'] = $this->audience;
        }

        return JWT::encode($payload, $this->secret, $this->algorithm);
    }

    /**
     * Decode and verify a token.
     *
     * @return array<string, mixed>
     * @throws TokenExpiredException
     * @throws TokenInvalidException
     */
    public function decode(string $token): array
    {
        $originalLeeway = JWT::$leeway;
        JWT::$leeway = $this->leeway;

        try {
            $payload = JWT::decode($token, new Key($this->secret, $this->algorithm));
            return $this->objectToArray($payload);
        } catch (ExpiredException $e) {
            throw new TokenExpiredException('Token has expired', ['original' => $e->getMessage()]);
        } catch (\Throwable $e) {
            throw new TokenInvalidException('Invalid token', ['original' => $e->getMessage()]);
        } finally {
            JWT::$leeway = $originalLeeway;
        }
    }

    /**
     * Decode with extra leeway (for refresh operations).
     *
     * @return array<string, mixed>
     * @throws TokenInvalidException
     */
    public function decodeWithLeeway(string $token, int $extraLeeway): array
    {
        $originalLeeway = JWT::$leeway;
        JWT::$leeway = max($this->leeway, $extraLeeway);

        try {
            $payload = JWT::decode($token, new Key($this->secret, $this->algorithm));
            return $this->objectToArray($payload);
        } catch (\Throwable $e) {
            throw new TokenInvalidException('Invalid token', ['original' => $e->getMessage()]);
        } finally {
            JWT::$leeway = $originalLeeway;
        }
    }

    /**
     * Verify a token and return as object.
     *
     * @throws TokenExpiredException
     * @throws TokenInvalidException
     */
    public function verify(string $token): object
    {
        return (object) $this->decode($token);
    }

    /**
     * Get token expiration time without full verification.
     * Useful for checking if refresh is needed.
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
                JSON_THROW_ON_ERROR
            );
            return $payload['exp'] ?? null;
        } catch (\Throwable) {
            return null;
        }
    }

    /**
     * Check if a token is expired (without throwing).
     */
    public function isExpired(string $token): bool
    {
        $exp = $this->getExpiration($token);
        return $exp === null || time() > $exp;
    }

    /**
     * Get the token ID (jti) claim.
     */
    public function getTokenId(string $token): ?string
    {
        try {
            $claims = $this->decodeWithLeeway($token, 86400 * 30); // 30 day leeway for ID extraction
            return $claims['jti'] ?? null;
        } catch (\Throwable) {
            return null;
        }
    }

    /**
     * Generate a unique token ID.
     */
    public function generateTokenId(): string
    {
        return bin2hex(random_bytes(16));
    }

    public function getAccessTtl(): int
    {
        return $this->accessTtl;
    }

    public function getRefreshTtl(): int
    {
        return $this->refreshTtl;
    }

    public function getLeeway(): int
    {
        return $this->leeway;
    }

    private function objectToArray(object $obj): array
    {
        return json_decode(json_encode($obj), true, 512, JSON_THROW_ON_ERROR);
    }
}
