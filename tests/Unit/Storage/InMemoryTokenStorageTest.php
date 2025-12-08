<?php

declare(strict_types=1);

namespace MonkeysLegion\Auth\Tests\Unit\Storage;

use MonkeysLegion\Auth\Storage\InMemoryTokenStorage;
use PHPUnit\Framework\TestCase;

class InMemoryTokenStorageTest extends TestCase
{
    private InMemoryTokenStorage $storage;

    protected function setUp(): void
    {
        $this->storage = new InMemoryTokenStorage();
    }

    public function test_store_saves_token_data(): void
    {
        $tokenId = 'test-token-123';
        $data = ['id' => 1, 'email' => 'test@example.com'];
        $ttl = 3600;

        $this->storage->store($tokenId, $data, $ttl);

        $this->assertTrue($this->storage->exists($tokenId));
        $this->assertEquals($data, $this->storage->get($tokenId));
    }

    public function test_exists_returns_false_for_nonexistent_token(): void
    {
        $this->assertFalse($this->storage->exists('nonexistent-token'));
    }

    public function test_exists_returns_false_for_expired_token(): void
    {
        $tokenId = 'expired-token';
        $data = ['id' => 1];

        // Store with 0 TTL (already expired)
        $this->storage->store($tokenId, $data, 0);

        // Sleep for 1 second to ensure expiration
        sleep(1);

        $this->assertFalse($this->storage->exists($tokenId));
    }

    public function test_exists_removes_expired_token(): void
    {
        $tokenId = 'expired-token';
        $data = ['id' => 1];

        $this->storage->store($tokenId, $data, 0);
        sleep(1);

        // First call to exists should remove the token
        $this->assertFalse($this->storage->exists($tokenId));

        // Second call should still return false
        $this->assertFalse($this->storage->exists($tokenId));
    }

    public function test_get_returns_null_for_nonexistent_token(): void
    {
        $this->assertNull($this->storage->get('nonexistent-token'));
    }

    public function test_get_returns_null_for_expired_token(): void
    {
        $tokenId = 'expired-token';
        $data = ['id' => 1];

        $this->storage->store($tokenId, $data, 0);
        sleep(1);

        $this->assertNull($this->storage->get($tokenId));
    }

    public function test_get_returns_stored_data(): void
    {
        $tokenId = 'test-token';
        $data = [
            'id' => 42,
            'email' => 'user@example.com',
            'roles' => ['admin', 'user'],
        ];

        $this->storage->store($tokenId, $data, 3600);

        $retrieved = $this->storage->get($tokenId);
        $this->assertEquals($data, $retrieved);
    }

    public function test_remove_deletes_token(): void
    {
        $tokenId = 'test-token';
        $data = ['id' => 1];

        $this->storage->store($tokenId, $data, 3600);
        $this->assertTrue($this->storage->exists($tokenId));

        $this->storage->remove($tokenId);

        $this->assertFalse($this->storage->exists($tokenId));
        $this->assertNull($this->storage->get($tokenId));
    }

    public function test_remove_nonexistent_token_does_not_error(): void
    {
        // Should not throw exception
        $this->storage->remove('nonexistent-token');
        $this->assertFalse($this->storage->exists('nonexistent-token'));
    }

    public function test_remove_all_for_user_removes_only_user_tokens(): void
    {
        $userId = 123;
        $otherUserId = 456;

        // Store tokens for user 123
        $this->storage->store('token-1', ['id' => $userId, 'name' => 'User 1'], 3600);
        $this->storage->store('token-2', ['id' => $userId, 'name' => 'User 1'], 3600);

        // Store tokens for user 456
        $this->storage->store('token-3', ['id' => $otherUserId, 'name' => 'User 2'], 3600);

        // Store token without user ID
        $this->storage->store('token-4', ['email' => 'test@example.com'], 3600);

        $this->storage->removeAllForUser($userId);

        // User 123 tokens should be removed
        $this->assertFalse($this->storage->exists('token-1'));
        $this->assertFalse($this->storage->exists('token-2'));

        // Other tokens should remain
        $this->assertTrue($this->storage->exists('token-3'));
        $this->assertTrue($this->storage->exists('token-4'));
    }

    public function test_remove_all_for_user_with_string_id(): void
    {
        $userId = 'user-uuid-123';

        $this->storage->store('token-1', ['id' => $userId], 3600);
        $this->storage->store('token-2', ['id' => $userId], 3600);
        $this->storage->store('token-3', ['id' => 'other-user'], 3600);

        $this->storage->removeAllForUser($userId);

        $this->assertFalse($this->storage->exists('token-1'));
        $this->assertFalse($this->storage->exists('token-2'));
        $this->assertTrue($this->storage->exists('token-3'));
    }

    public function test_blacklist_adds_token_to_blacklist(): void
    {
        $tokenId = 'blacklisted-token';

        $this->storage->blacklist($tokenId, 3600);

        $this->assertTrue($this->storage->isBlacklisted($tokenId));
    }

    public function test_is_blacklisted_returns_false_for_non_blacklisted_token(): void
    {
        $this->assertFalse($this->storage->isBlacklisted('not-blacklisted'));
    }

    public function test_is_blacklisted_returns_false_for_expired_blacklist(): void
    {
        $tokenId = 'expired-blacklist';

        $this->storage->blacklist($tokenId, 0);
        sleep(1);

        $this->assertFalse($this->storage->isBlacklisted($tokenId));
    }

    public function test_is_blacklisted_removes_expired_entry(): void
    {
        $tokenId = 'expired-blacklist';

        $this->storage->blacklist($tokenId, 0);
        sleep(1);

        // First call should remove it
        $this->assertFalse($this->storage->isBlacklisted($tokenId));

        // Second call should still return false
        $this->assertFalse($this->storage->isBlacklisted($tokenId));
    }

    public function test_blacklist_and_storage_are_independent(): void
    {
        $tokenId = 'test-token';
        $data = ['id' => 1];

        // Store a valid token
        $this->storage->store($tokenId, $data, 3600);
        $this->assertTrue($this->storage->exists($tokenId));

        // Blacklist the same token ID
        $this->storage->blacklist($tokenId, 3600);
        $this->assertTrue($this->storage->isBlacklisted($tokenId));

        // Token should still exist in storage
        $this->assertTrue($this->storage->exists($tokenId));
        $this->assertEquals($data, $this->storage->get($tokenId));

        // Remove from storage
        $this->storage->remove($tokenId);
        $this->assertFalse($this->storage->exists($tokenId));

        // Should still be blacklisted
        $this->assertTrue($this->storage->isBlacklisted($tokenId));
    }

    public function test_multiple_tokens_can_be_stored(): void
    {
        $tokens = [
            'token-1' => ['id' => 1, 'email' => 'user1@example.com'],
            'token-2' => ['id' => 2, 'email' => 'user2@example.com'],
            'token-3' => ['id' => 3, 'email' => 'user3@example.com'],
        ];

        foreach ($tokens as $tokenId => $data) {
            $this->storage->store($tokenId, $data, 3600);
        }

        foreach ($tokens as $tokenId => $expectedData) {
            $this->assertTrue($this->storage->exists($tokenId));
            $this->assertEquals($expectedData, $this->storage->get($tokenId));
        }
    }

    public function test_token_can_be_overwritten(): void
    {
        $tokenId = 'test-token';
        $originalData = ['id' => 1, 'email' => 'original@example.com'];
        $newData = ['id' => 2, 'email' => 'updated@example.com'];

        $this->storage->store($tokenId, $originalData, 3600);
        $this->assertEquals($originalData, $this->storage->get($tokenId));

        $this->storage->store($tokenId, $newData, 3600);
        $this->assertEquals($newData, $this->storage->get($tokenId));
    }

    public function test_ttl_is_respected(): void
    {
        $tokenId = 'short-lived-token';
        $data = ['id' => 1];

        // Store with 1 second TTL
        $this->storage->store($tokenId, $data, 1);

        // Should exist immediately
        $this->assertTrue($this->storage->exists($tokenId));

        // Wait for expiration
        sleep(2);

        // Should be expired now
        $this->assertFalse($this->storage->exists($tokenId));
    }
}
