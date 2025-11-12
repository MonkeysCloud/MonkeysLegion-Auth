<?php

declare(strict_types=1);

namespace MonkeysLegion\Auth;

use Firebase\JWT\ExpiredException;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use RuntimeException;
use PDOException;

/**
 * Service for issuing and verifying JSON Web Tokens (JWT).
 *
 * This service provides methods to issue JWTs with custom claims,
 * verify existing tokens, and decode them into associative arrays.
 */
final class JwtService
{
    private string $secret;
    private int $ttl;
    private int $leeway;
    private int $nbfSkew;

    public function __construct(string $secret, int $ttl = 3600, int $leeway = 0, int $nbfSkew = 0)
    {
        $this->secret  = $secret;
        $this->ttl     = $ttl;
        $this->leeway  = max(0, $leeway);
        $this->nbfSkew = max(0, $nbfSkew);
    }

    /**
     * Issue a JWT token with the given claims.
     *
     * @param array<string, mixed> $claims
     * @return string
     * @throws PDOException on database errors
     */
    public function issue(array $claims): string
    {
        $now = time();
        $payload = array_merge([
            'iat' => $now,
            'nbf' => $now - $this->nbfSkew,
            'exp' => $now + $this->ttl,
        ], $claims);

        return JWT::encode($payload, $this->secret, 'HS256');
    }

    /**
     * Verify a token and return the decoded payload.
     *
     * @param string $token
     * @return object
     * @throws RuntimeException on invalid token
     * @throws \JsonException
     */
    public function verify(string $token): object
    {
        $data = $this->decode($token);
        return (object)$data;
    }

    /**
     * Decode (and verify) a token, returning claims as an associative array.
     *
     * @param string $token
     * @return array<string,mixed>
     * @throws RuntimeException on invalid token
     * @throws \JsonException
     */
    public function decode(string $token): array
    {
        // allow small clock differences
        if ($this->leeway > 0) {
            JWT::$leeway = $this->leeway;
        }

        try {
            $payload = JWT::decode($token, new Key($this->secret, 'HS256'));
        } catch (ExpiredException $e) {
            throw new RuntimeException('Token expired', 401, $e);
        } catch (\Throwable $e) {
            throw new RuntimeException('Invalid token', 401, $e);
        }

        return json_decode(json_encode($payload), true, 512, JSON_THROW_ON_ERROR);
    }

    /**
     * Decode a token with extra leeway for clock skew, returning claims as an associative array.
     * This temporarily increases the leeway for this decode operation only.
     *
     * @param string $token
     * @param int $extraLeeway Additional seconds of leeway to allow (beyond configured leeway)
     * @return array<string,mixed>
     * @throws RuntimeException on invalid token
     * @throws \JsonException
     */
    public function decodeWithExtraLeeway(string $token, int $extraLeeway): array
    {
        $orig = JWT::$leeway;
        JWT::$leeway = max($orig, $extraLeeway);
        try {
            return $this->decode($token); // uses current leeway
        } finally {
            JWT::$leeway = $orig; // always restore
        }
    }

    /**
     * Get the default TTL for issued tokens.
     *
     * @return int Returns the default TTL (in seconds) for issued tokens.
     */
    public function getTtl(): int
    {
        return $this->ttl;
    }

    /**
     * Get the configured leeway for token verification.
     *
     * @return int Returns the configured leeway (in seconds) for token verification.
     */
    public function getLeeway(): int
    {
        return $this->leeway;
    }

    /**
     * Get the configured nbf skew for token issuance.
     *
     * @return int Returns the configured nbf skew (in seconds) for token issuance.
     */
    public function getNbfSkew(): int
    {
        return $this->nbfSkew;
    }

    /**
     * Extract the expiration time (exp claim) from a JWT token.
     *
     * @param string $token The JWT token.
     *
     * @return int The expiration time as a Unix timestamp, or 0 if not present.
     * @throws RuntimeException on invalid token
     * @throws \JsonException
     */
    public function getExpFrom(string $token): int
    {
        $claims = $this->decode($token);
        return (int) ($claims['exp'] ?? 0);
    }
}