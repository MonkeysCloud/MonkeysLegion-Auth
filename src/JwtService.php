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
    private int    $ttl;

    public function __construct(string $secret, int $ttl = 3600)
    {
        $this->secret = $secret;
        $this->ttl    = $ttl;
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
        $now     = time();
        $payload = array_merge([
            'iat' => $now,
            'nbf' => $now,
            'exp' => $now + $this->ttl
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
        try {
            // direct decode to catch ExpiredException specifically
            $payload = JWT::decode($token, new Key($this->secret, 'HS256'));
        } catch (ExpiredException $e) {
            throw new RuntimeException('Token expired', 401, $e);
        } catch (\Throwable $e) {
            throw new RuntimeException('Invalid token', 401, $e);
        }

        // convert stdClass payload to an associative array
        return json_decode(json_encode($payload), true, 512, JSON_THROW_ON_ERROR);
    }
}