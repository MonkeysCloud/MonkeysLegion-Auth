<?php

declare(strict_types=1);

namespace MonkeysLegion\Auth\Tests\Integration;

use MonkeysLegion\Auth\Service\AuthService;
use MonkeysLegion\Auth\Service\JwtService;
use MonkeysLegion\Auth\Service\PasswordHasher;
use MonkeysLegion\Auth\Exception\InvalidCredentialsException;
use MonkeysLegion\Auth\Exception\TokenRevokedException;
use MonkeysLegion\Auth\Tests\TestCase;
use MonkeysLegion\Auth\Tests\Fixtures\FakeUser;
use MonkeysLegion\Auth\Tests\Fixtures\FakeUserProvider;
use MonkeysLegion\Auth\Tests\Fixtures\FakeTokenStorage;

/**
 * Integration tests for complete authentication flows.
 */
class AuthenticationFlowTest extends TestCase
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
            secret: 'integration-test-secret-key-32-chars',
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

    public function testCompleteLoginLogoutFlow(): void
    {
        // 1. Register user
        $user = new FakeUser(
            id: 1,
            email: 'user@example.com',
            passwordHash: $this->hasher->hash('SecurePass123!'),
        );
        $this->users->addUser($user);

        // 2. Login
        $result = $this->auth->login('user@example.com', 'SecurePass123!');
        $this->assertTrue($result->success);
        $accessToken = $result->tokens->accessToken;
        $refreshToken = $result->tokens->refreshToken;

        // 3. Validate token works
        $claims = $this->auth->validateAccessToken($accessToken);
        $this->assertEquals(1, $claims['sub']);

        // 4. Get user from token
        $retrievedUser = $this->auth->getUserFromToken($accessToken);
        $this->assertNotNull($retrievedUser);
        $this->assertEquals('user@example.com', $retrievedUser->getEmail());

        // 5. Refresh token
        $newTokens = $this->auth->refresh($refreshToken);
        $this->assertNotEquals($accessToken, $newTokens->accessToken);

        // 6. Old refresh token should be blacklisted
        $oldTokenId = $this->jwt->getTokenId($refreshToken);
        $this->assertTrue($this->tokenStorage->isBlacklisted($oldTokenId));

        // 7. Logout
        $this->auth->logout($newTokens->accessToken);

        // 8. Token should be invalidated
        $logoutTokenId = $this->jwt->getTokenId($newTokens->accessToken);
        if ($logoutTokenId) {
            $this->assertTrue($this->tokenStorage->isBlacklisted($logoutTokenId));
        }
    }

    public function testFailedLoginAttempts(): void
    {
        $user = new FakeUser(
            id: 1,
            email: 'user@example.com',
            passwordHash: $this->hasher->hash('CorrectPassword'),
        );
        $this->users->addUser($user);

        // Multiple failed attempts
        for ($i = 0; $i < 3; $i++) {
            try {
                $this->auth->login('user@example.com', 'WrongPassword');
            } catch (InvalidCredentialsException) {
                // Expected
            }
        }

        // Correct password should still work (no rate limiter in this test)
        $result = $this->auth->login('user@example.com', 'CorrectPassword');
        $this->assertTrue($result->success);
    }

    public function testTokenVersionInvalidation(): void
    {
        $user = new FakeUser(
            id: 1,
            email: 'user@example.com',
            passwordHash: $this->hasher->hash('Password123'),
            tokenVersion: 1,
        );
        $this->users->addUser($user);

        // Login and get token
        $result = $this->auth->login('user@example.com', 'Password123');
        $accessToken = $result->tokens->accessToken;

        // Token should be valid
        $claims = $this->auth->validateAccessToken($accessToken);
        $this->assertEquals(1, $claims['sub']);

        // Simulate password change (increment token version)
        $this->users->incrementTokenVersion(1);

        // Token should now be invalid
        $this->expectException(TokenRevokedException::class);
        $this->auth->validateAccessToken($accessToken);
    }

    public function testLogoutAllDevices(): void
    {
        $user = new FakeUser(
            id: 1,
            email: 'user@example.com',
            passwordHash: $this->hasher->hash('Password123'),
            tokenVersion: 1,
        );
        $this->users->addUser($user);

        // Login from multiple "devices"
        $session1 = $this->auth->login('user@example.com', 'Password123');
        $session2 = $this->auth->login('user@example.com', 'Password123');

        // Logout from all devices
        $this->auth->logout($session1->tokens->accessToken, allDevices: true);

        // Token version should be incremented
        $updatedUser = $this->users->findById(1);
        $this->assertEquals(2, $updatedUser->tokenVersion);
    }

    public function testRefreshTokenRotation(): void
    {
        $user = new FakeUser(
            id: 1,
            email: 'user@example.com',
            passwordHash: $this->hasher->hash('Password123'),
        );
        $this->users->addUser($user);

        $result = $this->auth->login('user@example.com', 'Password123');
        $originalRefresh = $result->tokens->refreshToken;

        // First refresh
        $tokens1 = $this->auth->refresh($originalRefresh);
        
        // Original token should be blacklisted
        $originalId = $this->jwt->getTokenId($originalRefresh);
        $this->assertTrue($this->tokenStorage->isBlacklisted($originalId));

        // Second refresh with new token
        $tokens2 = $this->auth->refresh($tokens1->refreshToken);

        // First refresh token should also be blacklisted
        $tokens1Id = $this->jwt->getTokenId($tokens1->refreshToken);
        $this->assertTrue($this->tokenStorage->isBlacklisted($tokens1Id));

        // All tokens should be different
        $this->assertNotEquals($originalRefresh, $tokens1->refreshToken);
        $this->assertNotEquals($tokens1->refreshToken, $tokens2->refreshToken);
    }

    public function testMultipleUsersIsolation(): void
    {
        // Create two users
        $user1 = new FakeUser(
            id: 1,
            email: 'user1@example.com',
            passwordHash: $this->hasher->hash('Password1'),
        );
        $user2 = new FakeUser(
            id: 2,
            email: 'user2@example.com',
            passwordHash: $this->hasher->hash('Password2'),
        );
        $this->users->addUser($user1);
        $this->users->addUser($user2);

        // Login both users
        $result1 = $this->auth->login('user1@example.com', 'Password1');
        $result2 = $this->auth->login('user2@example.com', 'Password2');

        // Validate tokens return correct users
        $claims1 = $this->auth->validateAccessToken($result1->tokens->accessToken);
        $claims2 = $this->auth->validateAccessToken($result2->tokens->accessToken);

        $this->assertEquals(1, $claims1['sub']);
        $this->assertEquals(2, $claims2['sub']);

        // Logout user1 shouldn't affect user2
        $this->auth->logout($result1->tokens->accessToken);

        // User2's token should still work
        $this->auth->validateAccessToken($result2->tokens->accessToken);
        $this->assertTrue(true); // If we get here, token is still valid
    }
}
