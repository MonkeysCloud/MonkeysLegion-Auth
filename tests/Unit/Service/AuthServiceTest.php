<?php

declare(strict_types=1);

namespace MonkeysLegion\Auth\Tests\Unit\Service;

use MonkeysLegion\Auth\Service\AuthService;
use MonkeysLegion\Auth\Service\JwtService;
use MonkeysLegion\Auth\Service\PasswordHasher;
use MonkeysLegion\Auth\DTO\AuthResult;
use MonkeysLegion\Auth\DTO\TokenPair;
use MonkeysLegion\Auth\Exception\InvalidCredentialsException;
use MonkeysLegion\Auth\Exception\TokenRevokedException;
use MonkeysLegion\Auth\Exception\TokenInvalidException;
use MonkeysLegion\Auth\Tests\TestCase;
use MonkeysLegion\Auth\Tests\Fixtures\FakeUser;
use MonkeysLegion\Auth\Tests\Fixtures\FakeUserProvider;
use MonkeysLegion\Auth\Tests\Fixtures\FakeTokenStorage;

class AuthServiceTest extends TestCase
{
    private AuthService $auth;
    private JwtService $jwt;
    private PasswordHasher $hasher;
    private FakeUserProvider $users;
    private FakeTokenStorage $tokenStorage;

    protected function setUp(): void
    {
        parent::setUp();

        $this->jwt = new JwtService(
            secret: 'test-secret-key-at-least-32-characters-long',
            accessTtl: 1800,
            refreshTtl: 604800,
        );

        $this->hasher = new PasswordHasher();
        $this->users = new FakeUserProvider();
        $this->tokenStorage = new FakeTokenStorage();

        $this->auth = new AuthService(
            users: $this->users,
            hasher: $this->hasher,
            jwt: $this->jwt,
            tokenStorage: $this->tokenStorage,
        );
    }

    public function testLoginWithValidCredentials(): void
    {
        $user = new FakeUser(
            id: 1,
            email: 'test@example.com',
            passwordHash: $this->hasher->hash('password123'),
        );
        $this->users->addUser($user);

        $result = $this->auth->login('test@example.com', 'password123');

        $this->assertTrue($result->success);
        $this->assertFalse($result->requires2FA);
        $this->assertInstanceOf(TokenPair::class, $result->tokens);
        $this->assertNotEmpty($result->tokens->accessToken);
        $this->assertNotEmpty($result->tokens->refreshToken);
    }

    public function testLoginWithInvalidEmail(): void
    {
        $this->expectException(InvalidCredentialsException::class);

        $this->auth->login('nonexistent@example.com', 'password123');
    }

    public function testLoginWithInvalidPassword(): void
    {
        $user = new FakeUser(
            id: 1,
            email: 'test@example.com',
            passwordHash: $this->hasher->hash('password123'),
        );
        $this->users->addUser($user);

        $this->expectException(InvalidCredentialsException::class);

        $this->auth->login('test@example.com', 'wrongpassword');
    }

    public function testIssueTokenPair(): void
    {
        $user = new FakeUser(id: 1, email: 'test@example.com');

        $tokens = $this->auth->issueTokenPair($user);

        $this->assertInstanceOf(TokenPair::class, $tokens);
        $this->assertNotEmpty($tokens->accessToken);
        $this->assertNotEmpty($tokens->refreshToken);
        $this->assertGreaterThan(time(), $tokens->accessExpiresAt);
        $this->assertGreaterThan(time(), $tokens->refreshExpiresAt);
        $this->assertGreaterThan($tokens->accessExpiresAt, $tokens->refreshExpiresAt);
    }

    public function testValidateAccessToken(): void
    {
        $user = new FakeUser(id: 123, email: 'test@example.com');
        $tokens = $this->auth->issueTokenPair($user);

        $claims = $this->auth->validateAccessToken($tokens->accessToken);

        $this->assertEquals(123, $claims['sub']);
    }

    public function testValidateBlacklistedToken(): void
    {
        $user = new FakeUser(id: 1, email: 'test@example.com');
        $tokens = $this->auth->issueTokenPair($user);

        // Blacklist the token
        $tokenId = $this->jwt->getTokenId($tokens->accessToken);
        if ($tokenId) {
            $this->tokenStorage->blacklist($tokenId, 3600);
        }

        $this->expectException(TokenRevokedException::class);
        $this->auth->validateAccessToken($tokens->accessToken);
    }

    public function testRefreshToken(): void
    {
        $user = new FakeUser(id: 1, email: 'test@example.com');
        $this->users->addUser($user);
        
        $originalTokens = $this->auth->issueTokenPair($user);

        $newTokens = $this->auth->refresh($originalTokens->refreshToken);

        $this->assertInstanceOf(TokenPair::class, $newTokens);
        $this->assertNotEquals($originalTokens->accessToken, $newTokens->accessToken);
        $this->assertNotEquals($originalTokens->refreshToken, $newTokens->refreshToken);
    }

    public function testRefreshWithInvalidToken(): void
    {
        $this->expectException(TokenInvalidException::class);

        $this->auth->refresh('invalid.token.here');
    }

    public function testRefreshWithAccessTokenFails(): void
    {
        $user = new FakeUser(id: 1, email: 'test@example.com');
        $this->users->addUser($user);
        
        $tokens = $this->auth->issueTokenPair($user);

        $this->expectException(TokenInvalidException::class);

        // Try to use access token as refresh token
        $this->auth->refresh($tokens->accessToken);
    }

    public function testRefreshBlacklistsOldToken(): void
    {
        $user = new FakeUser(id: 1, email: 'test@example.com');
        $this->users->addUser($user);
        
        $originalTokens = $this->auth->issueTokenPair($user);
        $originalTokenId = $this->jwt->getTokenId($originalTokens->refreshToken);

        $this->auth->refresh($originalTokens->refreshToken);

        // Old token should be blacklisted
        $this->assertTrue($this->tokenStorage->isBlacklisted($originalTokenId));
    }

    public function testLogout(): void
    {
        $user = new FakeUser(id: 1, email: 'test@example.com');
        $this->users->addUser($user);
        
        $tokens = $this->auth->issueTokenPair($user);

        $this->auth->logout($tokens->accessToken);

        // Token should be blacklisted
        $tokenId = $this->jwt->getTokenId($tokens->accessToken);
        if ($tokenId) {
            $this->assertTrue($this->tokenStorage->isBlacklisted($tokenId));
        }
    }

    public function testLogoutAllDevices(): void
    {
        $user = new FakeUser(id: 1, email: 'test@example.com', tokenVersion: 1);
        $this->users->addUser($user);
        
        $tokens = $this->auth->issueTokenPair($user);

        $this->auth->logout($tokens->accessToken, allDevices: true);

        // Token version should be incremented
        $updatedUser = $this->users->findById(1);
        $this->assertEquals(2, $updatedUser->tokenVersion);
    }

    public function testGetUserFromToken(): void
    {
        $user = new FakeUser(id: 42, email: 'test@example.com');
        $this->users->addUser($user);
        
        $tokens = $this->auth->issueTokenPair($user);

        $retrievedUser = $this->auth->getUserFromToken($tokens->accessToken);

        $this->assertNotNull($retrievedUser);
        $this->assertEquals(42, $retrievedUser->getAuthIdentifier());
    }

    public function testGetUserFromInvalidToken(): void
    {
        $user = $this->auth->getUserFromToken('invalid.token');

        $this->assertNull($user);
    }

    public function testTokenVersionMismatchCausesRevocation(): void
    {
        $user = new FakeUser(id: 1, email: 'test@example.com', tokenVersion: 1);
        $this->users->addUser($user);
        
        $tokens = $this->auth->issueTokenPair($user);

        // Increment token version (simulating password change)
        $this->users->incrementTokenVersion(1);

        $this->expectException(TokenRevokedException::class);

        $this->auth->validateAccessToken($tokens->accessToken);
    }

    public function testLoginWith2FARequired(): void
    {
        $user = new FakeUser(
            id: 1,
            email: 'test@example.com',
            passwordHash: $this->hasher->hash('password123'),
            twoFactorSecret: 'JBSWY3DPEHPK3PXP', // Test secret
        );
        $this->users->addUser($user);

        $result = $this->auth->login('test@example.com', 'password123');

        $this->assertFalse($result->success);
        $this->assertTrue($result->requires2FA);
        $this->assertNotEmpty($result->challengeToken);
    }

    public function testAuthResultSuccess(): void
    {
        $user = new FakeUser(id: 1);
        $tokens = new TokenPair('access', 'refresh', time() + 3600, time() + 86400);

        $result = AuthResult::success($user, $tokens);

        $this->assertTrue($result->success);
        $this->assertFalse($result->requires2FA);
        $this->assertSame($user, $result->user);
        $this->assertSame($tokens, $result->tokens);
    }

    public function testAuthResultRequires2FA(): void
    {
        $result = AuthResult::requires2FA('challenge-token');

        $this->assertFalse($result->success);
        $this->assertTrue($result->requires2FA);
        $this->assertEquals('challenge-token', $result->challengeToken);
        $this->assertNull($result->user);
        $this->assertNull($result->tokens);
    }
}
