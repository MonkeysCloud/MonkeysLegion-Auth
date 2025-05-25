<?php

declare(strict_types=1);

namespace MonkeysLegion\Auth;

use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use RuntimeException;

final class JwtService
{
    private string $secret;
    private int    $ttl;

    public function __construct(string $secret, int $ttl = 3600)
    {
        $this->secret = $secret;
        $this->ttl    = $ttl;
    }

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

    public function verify(string $token): object
    {
        try {
            return JWT::decode($token, new Key($this->secret, 'HS256'));
        } catch (\Throwable $e) {
            throw new RuntimeException('Invalid JWT token', 0, $e);
        }
    }
}