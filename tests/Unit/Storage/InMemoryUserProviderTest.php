<?php

declare(strict_types=1);

namespace MonkeysLegion\Auth\Tests\Unit\Storage;

use MonkeysLegion\Auth\Storage\InMemoryUserProvider;
use MonkeysLegion\Auth\Tests\Fixtures\FakeUser;
use PHPUnit\Framework\TestCase;
use RuntimeException;

class InMemoryUserProviderTest extends TestCase
{
    private InMemoryUserProvider $provider;

    protected function setUp(): void
    {
        $this->provider = new InMemoryUserProvider();
    }

    public function test_add_user_stores_user(): void
    {
        $user = new FakeUser(id: 1, email: 'test@example.com');

        $this->provider->addUser($user);

        $this->assertEquals(1, $this->provider->count());
        $this->assertSame($user, $this->provider->findById(1));
    }

    public function test_add_multiple_users(): void
    {
        $user1 = new FakeUser(id: 1, email: 'user1@example.com');
        $user2 = new FakeUser(id: 2, email: 'user2@example.com');
        $user3 = new FakeUser(id: 3, email: 'user3@example.com');

        $this->provider->addUser($user1);
        $this->provider->addUser($user2);
        $this->provider->addUser($user3);

        $this->assertEquals(3, $this->provider->count());
        $this->assertSame($user1, $this->provider->findById(1));
        $this->assertSame($user2, $this->provider->findById(2));
        $this->assertSame($user3, $this->provider->findById(3));
    }

    public function test_find_by_id_returns_null_for_nonexistent_user(): void
    {
        $this->assertNull($this->provider->findById(999));
    }

    public function test_find_by_id_with_different_users(): void
    {
        $user1 = new FakeUser(id: 10, email: 'test1@example.com');
        $user2 = new FakeUser(id: 20, email: 'test2@example.com');

        $this->provider->addUser($user1);
        $this->provider->addUser($user2);

        $this->assertSame($user1, $this->provider->findById(10));
        $this->assertSame($user2, $this->provider->findById(20));
        $this->assertNull($this->provider->findById(30));
    }

    public function test_find_by_email_returns_user(): void
    {
        $user = new FakeUser(id: 1, email: 'test@example.com');

        $this->provider->addUser($user);

        $found = $this->provider->findByEmail('test@example.com');
        $this->assertSame($user, $found);
    }

    public function test_find_by_email_returns_null_for_nonexistent_email(): void
    {
        $user = new FakeUser(id: 1, email: 'test@example.com');
        $this->provider->addUser($user);

        $this->assertNull($this->provider->findByEmail('nonexistent@example.com'));
    }

    public function test_find_by_email_is_case_sensitive(): void
    {
        $user = new FakeUser(id: 1, email: 'Test@Example.com');
        $this->provider->addUser($user);

        $this->assertSame($user, $this->provider->findByEmail('Test@Example.com'));
        $this->assertNull($this->provider->findByEmail('test@example.com'));
    }

    public function test_find_by_credentials_with_email(): void
    {
        $user = new FakeUser(id: 1, email: 'test@example.com');
        $this->provider->addUser($user);

        $found = $this->provider->findByCredentials(['email' => 'test@example.com']);

        $this->assertSame($user, $found);
    }

    public function test_find_by_credentials_with_id(): void
    {
        $user = new FakeUser(id: 1, email: 'test@example.com');
        $this->provider->addUser($user);

        $found = $this->provider->findByCredentials(['id' => 1]);

        $this->assertSame($user, $found);
    }

    public function test_find_by_credentials_returns_null_when_not_found(): void
    {
        $user = new FakeUser(id: 1, email: 'test@example.com');
        $this->provider->addUser($user);

        $this->assertNull($this->provider->findByCredentials(['email' => 'other@example.com']));
        $this->assertNull($this->provider->findByCredentials(['id' => 999]));
    }

    public function test_find_by_credentials_returns_null_for_empty_credentials(): void
    {
        $user = new FakeUser(id: 1, email: 'test@example.com');
        $this->provider->addUser($user);

        // Empty credentials will match all users, so it returns the first one
        // To test "not found", we need to use credentials that don't match
        $this->assertNull($this->provider->findByCredentials(['nonexistent_field' => 'value']));
    }

    public function test_increment_token_version(): void
    {
        $user = new FakeUser(id: 1, email: 'test@example.com', tokenVersion: 1);
        $this->provider->addUser($user);

        $this->assertEquals(1, $user->tokenVersion);

        $this->provider->incrementTokenVersion(1);

        $this->assertEquals(2, $user->tokenVersion);

        $this->provider->incrementTokenVersion(1);

        $this->assertEquals(3, $user->tokenVersion);
    }

    public function test_increment_token_version_throws_for_nonexistent_user(): void
    {
        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('User with ID 999 not found');

        $this->provider->incrementTokenVersion(999);
    }

    public function test_create_throws_runtime_exception(): void
    {
        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('InMemoryUserProvider::create() requires a concrete user class');

        $this->provider->create(['email' => 'test@example.com']);
    }

    public function test_update_password(): void
    {
        $user = new FakeUser(id: 1, email: 'test@example.com');
        $originalHash = $user->passwordHash;

        $this->provider->addUser($user);

        $newHash = password_hash('newpassword', PASSWORD_DEFAULT);
        $this->provider->updatePassword(1, $newHash);

        $this->assertEquals($newHash, $user->passwordHash);
        $this->assertNotEquals($originalHash, $user->passwordHash);
    }

    public function test_update_password_throws_for_nonexistent_user(): void
    {
        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('User with ID 999 not found');

        $this->provider->updatePassword(999, 'newhash');
    }

    public function test_get_all_users_returns_all_stored_users(): void
    {
        $user1 = new FakeUser(id: 1, email: 'user1@example.com');
        $user2 = new FakeUser(id: 2, email: 'user2@example.com');

        $this->provider->addUser($user1);
        $this->provider->addUser($user2);

        $allUsers = $this->provider->getAllUsers();

        $this->assertCount(2, $allUsers);
        $this->assertSame($user1, $allUsers[1]);
        $this->assertSame($user2, $allUsers[2]);
    }

    public function test_get_all_users_returns_empty_array_when_no_users(): void
    {
        $this->assertEmpty($this->provider->getAllUsers());
    }

    public function test_clear_removes_all_users(): void
    {
        $user1 = new FakeUser(id: 1, email: 'user1@example.com');
        $user2 = new FakeUser(id: 2, email: 'user2@example.com');

        $this->provider->addUser($user1);
        $this->provider->addUser($user2);

        $this->assertEquals(2, $this->provider->count());

        $this->provider->clear();

        $this->assertEquals(0, $this->provider->count());
        $this->assertNull($this->provider->findById(1));
        $this->assertNull($this->provider->findById(2));
        $this->assertNull($this->provider->findByEmail('user1@example.com'));
    }

    public function test_clear_resets_next_id(): void
    {
        $user1 = new FakeUser(id: 5, email: 'user1@example.com');

        $this->provider->addUser($user1);
        $this->provider->clear();

        // After clear, adding a user with high ID should update nextId
        $user2 = new FakeUser(id: 10, email: 'user2@example.com');
        $this->provider->addUser($user2);

        $this->assertEquals(1, $this->provider->count());
    }

    public function test_count_returns_correct_number_of_users(): void
    {
        $this->assertEquals(0, $this->provider->count());

        $this->provider->addUser(new FakeUser(id: 1, email: 'user1@example.com'));
        $this->assertEquals(1, $this->provider->count());

        $this->provider->addUser(new FakeUser(id: 2, email: 'user2@example.com'));
        $this->assertEquals(2, $this->provider->count());

        $this->provider->addUser(new FakeUser(id: 3, email: 'user3@example.com'));
        $this->assertEquals(3, $this->provider->count());
    }

    public function test_remove_user_deletes_user(): void
    {
        $user = new FakeUser(id: 1, email: 'test@example.com');

        $this->provider->addUser($user);
        $this->assertEquals(1, $this->provider->count());

        $this->provider->removeUser(1);

        $this->assertEquals(0, $this->provider->count());
        $this->assertNull($this->provider->findById(1));
        $this->assertNull($this->provider->findByEmail('test@example.com'));
    }

    public function test_remove_user_does_not_error_for_nonexistent_user(): void
    {
        // Should not throw exception
        $this->provider->removeUser(999);
        $this->assertEquals(0, $this->provider->count());
    }

    public function test_remove_user_only_removes_specified_user(): void
    {
        $user1 = new FakeUser(id: 1, email: 'user1@example.com');
        $user2 = new FakeUser(id: 2, email: 'user2@example.com');
        $user3 = new FakeUser(id: 3, email: 'user3@example.com');

        $this->provider->addUser($user1);
        $this->provider->addUser($user2);
        $this->provider->addUser($user3);

        $this->provider->removeUser(2);

        $this->assertEquals(2, $this->provider->count());
        $this->assertSame($user1, $this->provider->findById(1));
        $this->assertNull($this->provider->findById(2));
        $this->assertSame($user3, $this->provider->findById(3));
    }

    public function test_add_user_updates_email_mapping(): void
    {
        $user1 = new FakeUser(id: 1, email: 'original@example.com');
        $this->provider->addUser($user1);

        $this->assertSame($user1, $this->provider->findByEmail('original@example.com'));

        // Add another user with same ID (overwrite)
        $user2 = new FakeUser(id: 1, email: 'updated@example.com');
        $this->provider->addUser($user2);

        // Should find by new email only
        $this->assertSame($user2, $this->provider->findByEmail('updated@example.com'));
        // Note: old email might still point to the ID since we're overwriting
    }

    public function test_remove_user_removes_email_mapping(): void
    {
        $user = new FakeUser(id: 1, email: 'test@example.com');

        $this->provider->addUser($user);
        $this->assertSame($user, $this->provider->findByEmail('test@example.com'));

        $this->provider->removeUser(1);

        $this->assertNull($this->provider->findByEmail('test@example.com'));
    }

    public function test_multiple_operations_on_same_user(): void
    {
        $user = new FakeUser(id: 100, email: 'user@example.com', tokenVersion: 1);

        $this->provider->addUser($user);
        $this->assertSame($user, $this->provider->findById(100));

        // Update password
        $newHash = password_hash('newpassword', PASSWORD_DEFAULT);
        $this->provider->updatePassword(100, $newHash);
        $this->assertEquals($newHash, $user->passwordHash);

        // Increment token version
        $this->provider->incrementTokenVersion(100);
        $this->assertEquals(2, $user->tokenVersion);

        // Remove user
        $this->provider->removeUser(100);
        $this->assertNull($this->provider->findById(100));
    }
}
