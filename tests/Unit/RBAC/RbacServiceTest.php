<?php

declare(strict_types=1);

namespace MonkeysLegion\Auth\Tests\Unit\RBAC;

use MonkeysLegion\Auth\RBAC\RoleRegistry;
use MonkeysLegion\Auth\RBAC\PermissionChecker;
use MonkeysLegion\Auth\Tests\TestCase;
use MonkeysLegion\Auth\Tests\Fixtures\FakeUser;

class RbacServiceTest extends TestCase
{
    private RoleRegistry $roles;
    private PermissionChecker $checker;

    protected function setUp(): void
    {
        parent::setUp();
        
        $this->roles = new RoleRegistry();
        $this->roles->registerFromConfig([
            'admin' => [
                'permissions' => ['*'],
                'description' => 'Full access',
            ],
            'editor' => [
                'permissions' => ['posts.*', 'media.*'],
                'description' => 'Content management',
            ],
            'author' => [
                'permissions' => ['posts.create', 'posts.edit-own', 'posts.view'],
                'inherits' => ['viewer'],
            ],
            'viewer' => [
                'permissions' => ['posts.view', 'media.view'],
            ],
        ]);

        $this->checker = new PermissionChecker($this->roles);
    }

    public function testAdminHasAllPermissions(): void
    {
        $user = new FakeUser(roles: ['admin']);

        $this->assertTrue($this->checker->can($user, 'posts.create'));
        $this->assertTrue($this->checker->can($user, 'posts.delete'));
        $this->assertTrue($this->checker->can($user, 'users.manage'));
        $this->assertTrue($this->checker->can($user, 'any.permission'));
    }

    public function testEditorHasWildcardPermissions(): void
    {
        $user = new FakeUser(roles: ['editor']);

        $this->assertTrue($this->checker->can($user, 'posts.create'));
        $this->assertTrue($this->checker->can($user, 'posts.edit'));
        $this->assertTrue($this->checker->can($user, 'posts.delete'));
        $this->assertTrue($this->checker->can($user, 'media.upload'));
        
        // Should not have user management
        $this->assertFalse($this->checker->can($user, 'users.manage'));
    }

    public function testAuthorHasSpecificPermissions(): void
    {
        $user = new FakeUser(roles: ['author']);

        $this->assertTrue($this->checker->can($user, 'posts.create'));
        $this->assertTrue($this->checker->can($user, 'posts.edit-own'));
        $this->assertTrue($this->checker->can($user, 'posts.view'));
        
        // Should not have delete
        $this->assertFalse($this->checker->can($user, 'posts.delete'));
    }

    public function testAuthorInheritsViewerPermissions(): void
    {
        $user = new FakeUser(roles: ['author']);

        // Inherited from viewer
        $this->assertTrue($this->checker->can($user, 'media.view'));
    }

    public function testViewerHasLimitedPermissions(): void
    {
        $user = new FakeUser(roles: ['viewer']);

        $this->assertTrue($this->checker->can($user, 'posts.view'));
        $this->assertTrue($this->checker->can($user, 'media.view'));
        
        $this->assertFalse($this->checker->can($user, 'posts.create'));
        $this->assertFalse($this->checker->can($user, 'posts.edit'));
    }

    public function testUserWithNoRolesHasNoPermissions(): void
    {
        $user = new FakeUser(roles: []);

        $this->assertFalse($this->checker->can($user, 'posts.view'));
        $this->assertFalse($this->checker->can($user, 'anything'));
    }

    public function testUserWithMultipleRoles(): void
    {
        $user = new FakeUser(roles: ['author', 'editor']);

        // From author
        $this->assertTrue($this->checker->can($user, 'posts.edit-own'));
        
        // From editor
        $this->assertTrue($this->checker->can($user, 'media.upload'));
        $this->assertTrue($this->checker->can($user, 'posts.delete'));
    }

    public function testDirectUserPermissions(): void
    {
        $user = new FakeUser(
            roles: ['viewer'],
            permissions: ['special.action'],
        );

        // From role
        $this->assertTrue($this->checker->can($user, 'posts.view'));
        
        // Direct permission
        $this->assertTrue($this->checker->can($user, 'special.action'));
    }

    public function testHasRoleCheck(): void
    {
        $user = new FakeUser(roles: ['admin', 'editor']);

        $this->assertTrue($this->checker->hasRole($user, 'admin'));
        $this->assertTrue($this->checker->hasRole($user, 'editor'));
        $this->assertFalse($this->checker->hasRole($user, 'viewer'));
    }

    public function testHasAnyRole(): void
    {
        $user = new FakeUser(roles: ['author']);

        $this->assertTrue($this->checker->hasAnyRole($user, ['admin', 'author']));
        $this->assertFalse($this->checker->hasAnyRole($user, ['admin', 'editor']));
    }

    public function testHasAllRoles(): void
    {
        $user = new FakeUser(roles: ['admin', 'editor']);

        $this->assertTrue($this->checker->hasAllRoles($user, ['admin', 'editor']));
        $this->assertFalse($this->checker->hasAllRoles($user, ['admin', 'editor', 'viewer']));
    }

    public function testGetRolePermissions(): void
    {
        $permissions = $this->roles->getRolePermissions('editor');

        $this->assertContains('posts.*', $permissions);
        $this->assertContains('media.*', $permissions);
    }

    public function testGetAllUserPermissions(): void
    {
        $user = new FakeUser(
            roles: ['author'],
            permissions: ['custom.permission'],
        );

        $permissions = $this->checker->getAllPermissions($user);

        $this->assertContains('posts.create', $permissions);
        $this->assertContains('posts.edit-own', $permissions);
        $this->assertContains('custom.permission', $permissions);
        // Inherited from viewer
        $this->assertContains('media.view', $permissions);
    }

    public function testRegisterRole(): void
    {
        $this->roles->register('moderator', ['posts.moderate', 'comments.delete']);

        $user = new FakeUser(roles: ['moderator']);

        $this->assertTrue($this->checker->can($user, 'posts.moderate'));
        $this->assertTrue($this->checker->can($user, 'comments.delete'));
    }

    public function testRoleExists(): void
    {
        $this->assertTrue($this->roles->exists('admin'));
        $this->assertTrue($this->roles->exists('editor'));
        $this->assertFalse($this->roles->exists('nonexistent'));
    }

    public function testGetAllRoles(): void
    {
        $allRoles = $this->roles->all();

        $this->assertArrayHasKey('admin', $allRoles);
        $this->assertArrayHasKey('editor', $allRoles);
        $this->assertArrayHasKey('author', $allRoles);
        $this->assertArrayHasKey('viewer', $allRoles);
    }
}
