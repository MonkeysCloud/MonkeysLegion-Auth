<?php

declare(strict_types=1);

namespace MonkeysLegion\Auth\Tests\Unit\Policy;

use MonkeysLegion\Auth\Policy\Gate;
use MonkeysLegion\Auth\Policy\AbstractPolicy;
use MonkeysLegion\Auth\Exception\UnauthorizedException;
use MonkeysLegion\Auth\Tests\TestCase;
use MonkeysLegion\Auth\Tests\Fixtures\FakeUser;

// Test model
class Post
{
    public function __construct(
        public int $id,
        public int $authorId,
        public bool $published = false,
    ) {}
}

// Test policy
class PostPolicy extends AbstractPolicy
{
    public function view(?object $user, Post $post): bool
    {
        return $post->published || ($user && $user->id === $post->authorId);
    }

    public function edit(?object $user, Post $post): bool
    {
        return $user && $user->id === $post->authorId;
    }

    public function delete(?object $user, Post $post): bool
    {
        return $user && $user->id === $post->authorId;
    }

    public function before(?object $user, string $ability, ?object $model = null): ?bool
    {
        // Admins can do anything
        if ($user && method_exists($user, 'hasRole') && $user->hasRole('admin')) {
            return true;
        }
        return null;
    }
}

class GateTest extends TestCase
{
    private Gate $gate;

    protected function setUp(): void
    {
        parent::setUp();
        $this->gate = new Gate();
    }

    public function testDefineAbility(): void
    {
        $this->gate->define('view-dashboard', function (?object $user) {
            return $user !== null;
        });

        $user = new FakeUser();
        
        $this->assertTrue($this->gate->allows($user, 'view-dashboard'));
        $this->assertFalse($this->gate->allows(null, 'view-dashboard'));
    }

    public function testDenies(): void
    {
        $this->gate->define('admin-only', function (?object $user) {
            return $user && $user->hasRole('admin');
        });

        $normalUser = new FakeUser(roles: ['user']);
        $adminUser = new FakeUser(roles: ['admin']);

        $this->assertTrue($this->gate->denies($normalUser, 'admin-only'));
        $this->assertFalse($this->gate->denies($adminUser, 'admin-only'));
    }

    public function testAuthorizeThrowsOnDenied(): void
    {
        $this->gate->define('restricted', fn() => false);

        $this->expectException(UnauthorizedException::class);

        $this->gate->authorize(new FakeUser(), 'restricted');
    }

    public function testAuthorizePassesOnAllowed(): void
    {
        $this->gate->define('allowed', fn() => true);

        // Should not throw
        $this->gate->authorize(new FakeUser(), 'allowed');
        $this->assertTrue(true);
    }

    public function testPolicyRegistration(): void
    {
        $this->gate->policy(Post::class, PostPolicy::class);

        $user = new FakeUser(id: 1);
        $ownPost = new Post(1, authorId: 1);
        $otherPost = new Post(2, authorId: 2);

        $this->assertTrue($this->gate->allows($user, 'edit', $ownPost));
        $this->assertFalse($this->gate->allows($user, 'edit', $otherPost));
    }

    public function testPolicyViewPublished(): void
    {
        $this->gate->policy(Post::class, PostPolicy::class);

        $user = new FakeUser(id: 1);
        $publishedPost = new Post(1, authorId: 2, published: true);
        $draftPost = new Post(2, authorId: 2, published: false);

        $this->assertTrue($this->gate->allows($user, 'view', $publishedPost));
        $this->assertFalse($this->gate->allows($user, 'view', $draftPost));
    }

    public function testPolicyBeforeHook(): void
    {
        $this->gate->policy(Post::class, PostPolicy::class);

        $admin = new FakeUser(id: 999, roles: ['admin']);
        $otherPost = new Post(1, authorId: 1);

        // Admin should bypass normal checks
        $this->assertTrue($this->gate->allows($admin, 'edit', $otherPost));
        $this->assertTrue($this->gate->allows($admin, 'delete', $otherPost));
    }

    public function testGateBeforeCallback(): void
    {
        $this->gate->before(function (?object $user, string $ability) {
            if ($user && $user->id === 999) {
                return true; // Super user
            }
            return null;
        });

        $this->gate->define('anything', fn() => false);

        $superUser = new FakeUser(id: 999);
        $normalUser = new FakeUser(id: 1);

        $this->assertTrue($this->gate->allows($superUser, 'anything'));
        $this->assertFalse($this->gate->allows($normalUser, 'anything'));
    }

    public function testGateAfterCallback(): void
    {
        $loggedAbilities = [];

        $this->gate->after(function (?object $user, string $ability, bool $result) use (&$loggedAbilities) {
            $loggedAbilities[] = ['ability' => $ability, 'result' => $result];
            return null;
        });

        $this->gate->define('test', fn() => true);

        $this->gate->allows(new FakeUser(), 'test');

        $this->assertCount(1, $loggedAbilities);
        $this->assertEquals('test', $loggedAbilities[0]['ability']);
        $this->assertTrue($loggedAbilities[0]['result']);
    }

    public function testAllAbilities(): void
    {
        $this->gate->define('ability1', fn() => true);
        $this->gate->define('ability2', fn() => true);
        $this->gate->define('ability3', fn() => false);

        $user = new FakeUser();

        $this->assertTrue($this->gate->all($user, ['ability1', 'ability2']));
        $this->assertFalse($this->gate->all($user, ['ability1', 'ability3']));
    }

    public function testAnyAbility(): void
    {
        $this->gate->define('ability1', fn() => false);
        $this->gate->define('ability2', fn() => true);

        $user = new FakeUser();

        $this->assertTrue($this->gate->any($user, ['ability1', 'ability2']));
        $this->assertFalse($this->gate->any($user, ['ability1']));
    }

    public function testAbilityWithArguments(): void
    {
        $this->gate->define('edit-post', function (?object $user, Post $post) {
            return $user && $user->id === $post->authorId;
        });

        $user = new FakeUser(id: 1);
        $ownPost = new Post(1, authorId: 1);
        $otherPost = new Post(2, authorId: 2);

        $this->assertTrue($this->gate->allows($user, 'edit-post', $ownPost));
        $this->assertFalse($this->gate->allows($user, 'edit-post', $otherPost));
    }

    public function testGuestAccess(): void
    {
        $this->gate->define('view-public', fn() => true);
        $this->gate->define('view-private', fn(?object $user) => $user !== null);

        $this->assertTrue($this->gate->allows(null, 'view-public'));
        $this->assertFalse($this->gate->allows(null, 'view-private'));
    }

    public function testUndefinedAbilityDenied(): void
    {
        $user = new FakeUser();

        $this->assertFalse($this->gate->allows($user, 'undefined-ability'));
    }
}
