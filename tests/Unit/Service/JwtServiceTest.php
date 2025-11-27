<?php

declare(strict_types=1);

namespace MonkeysLegion\Auth\Tests\Unit\Service;

use MonkeysLegion\Auth\Service\JwtService;
use MonkeysLegion\Auth\Exception\TokenExpiredException;
use MonkeysLegion\Auth\Exception\TokenInvalidException;
use MonkeysLegion\Auth\Tests\TestCase;

class JwtServiceTest extends TestCase
{
    private JwtService $jwt;
    private string $secret = 'test-secret-key-at-least-32-characters-long';

    protected function setUp(): void
    {
        parent::setUp();
        $this->jwt = new JwtService(
            secret: $this->secret,
            accessTtl: 1800,
            refreshTtl: 604800,
        );
    }

    public function testIssueAccessToken(): void
    {
        $token = $this->jwt->issueAccessToken(['sub' => 123]);

        $this->assertIsString($token);
        $this->assertNotEmpty($token);
        
        // JWT has 3 parts
        $parts = explode('.', $token);
        $this->assertCount(3, $parts);
    }

    public function testIssueRefreshToken(): void
    {
        $token = $this->jwt->issueRefreshToken(['sub' => 123]);

        $this->assertIsString($token);
        
        $claims = $this->jwt->decode($token);
        $this->assertEquals('refresh', $claims['type']);
        $this->assertArrayHasKey('jti', $claims);
    }

    public function testDecodeValidToken(): void
    {
        $token = $this->jwt->issueAccessToken([
            'sub' => 123,
            'email' => 'test@example.com',
        ]);

        $claims = $this->jwt->decode($token);

        $this->assertEquals(123, $claims['sub']);
        $this->assertEquals('test@example.com', $claims['email']);
        $this->assertArrayHasKey('iat', $claims);
        $this->assertArrayHasKey('exp', $claims);
        $this->assertArrayHasKey('nbf', $claims);
    }

    public function testDecodeInvalidToken(): void
    {
        $this->expectException(TokenInvalidException::class);
        
        $this->jwt->decode('invalid.token.here');
    }

    public function testDecodeExpiredToken(): void
    {
        // Create a service with very short TTL
        $jwt = new JwtService(
            secret: $this->secret,
            accessTtl: -1, // Already expired
        );

        $token = $jwt->issueAccessToken(['sub' => 123]);

        $this->expectException(TokenExpiredException::class);
        $jwt->decode($token);
    }

    public function testDecodeWithLeeway(): void
    {
        // Create expired token
        $jwt = new JwtService(
            secret: $this->secret,
            accessTtl: -10, // 10 seconds ago
        );

        $token = $jwt->issueAccessToken(['sub' => 123]);

        // Should fail without leeway
        try {
            $jwt->decode($token);
            $this->fail('Expected TokenExpiredException');
        } catch (TokenExpiredException) {
            // Expected
        }

        // Should succeed with leeway
        $claims = $jwt->decodeWithLeeway($token, 60);
        $this->assertEquals(123, $claims['sub']);
    }

    public function testGetExpiration(): void
    {
        $token = $this->jwt->issueAccessToken(['sub' => 123]);

        $exp = $this->jwt->getExpiration($token);

        $this->assertIsInt($exp);
        $this->assertGreaterThan(time(), $exp);
        $this->assertLessThanOrEqual(time() + 1800 + 5, $exp); // +5 for test execution time
    }

    public function testGetExpirationInvalidToken(): void
    {
        $exp = $this->jwt->getExpiration('invalid');
        $this->assertNull($exp);
    }

    public function testIsExpired(): void
    {
        $token = $this->jwt->issueAccessToken(['sub' => 123]);
        $this->assertFalse($this->jwt->isExpired($token));

        // Create expired token
        $jwt = new JwtService(secret: $this->secret, accessTtl: -1);
        $expiredToken = $jwt->issueAccessToken(['sub' => 123]);
        $this->assertTrue($jwt->isExpired($expiredToken));
    }

    public function testGetTokenId(): void
    {
        $token = $this->jwt->issueRefreshToken(['sub' => 123]);
        
        $tokenId = $this->jwt->getTokenId($token);
        
        $this->assertIsString($tokenId);
        $this->assertNotEmpty($tokenId);
    }

    public function testGenerateTokenId(): void
    {
        $id1 = $this->jwt->generateTokenId();
        $id2 = $this->jwt->generateTokenId();

        $this->assertIsString($id1);
        $this->assertIsString($id2);
        $this->assertNotEquals($id1, $id2);
        $this->assertEquals(32, strlen($id1)); // 16 bytes = 32 hex chars
    }

    public function testIssueWithCustomClaims(): void
    {
        $token = $this->jwt->issueAccessToken([
            'sub' => 123,
            'roles' => ['admin', 'user'],
            'custom' => 'value',
        ]);

        $claims = $this->jwt->decode($token);

        $this->assertEquals(['admin', 'user'], $claims['roles']);
        $this->assertEquals('value', $claims['custom']);
    }

    public function testIssueWithIssuerAndAudience(): void
    {
        $jwt = new JwtService(
            secret: $this->secret,
            accessTtl: 1800,
            issuer: 'my-app',
            audience: 'my-api',
        );

        $token = $jwt->issueAccessToken(['sub' => 123]);
        $claims = $jwt->decode($token);

        $this->assertEquals('my-app', $claims['iss']);
        $this->assertEquals('my-api', $claims['aud']);
    }

    public function testGetAccessTtl(): void
    {
        $this->assertEquals(1800, $this->jwt->getAccessTtl());
    }

    public function testGetRefreshTtl(): void
    {
        $this->assertEquals(604800, $this->jwt->getRefreshTtl());
    }

    public function testTokenWithDifferentSecretFails(): void
    {
        $token = $this->jwt->issueAccessToken(['sub' => 123]);

        $otherJwt = new JwtService(secret: 'different-secret-key-at-least-32-chars');

        $this->expectException(TokenInvalidException::class);
        $otherJwt->decode($token);
    }

    public function testVerifyReturnsObject(): void
    {
        $token = $this->jwt->issueAccessToken(['sub' => 123]);
        
        $claims = $this->jwt->verify($token);
        
        $this->assertIsObject($claims);
        $this->assertEquals(123, $claims->sub);
    }
}
