<?php

declare(strict_types=1);

namespace MonkeysLegion\Auth\Tests\Unit\Exception;

use MonkeysLegion\Auth\Exception\AuthException;
use MonkeysLegion\Auth\Exception\InvalidCredentialsException;
use MonkeysLegion\Auth\Exception\TokenExpiredException;
use MonkeysLegion\Auth\Exception\TokenInvalidException;
use MonkeysLegion\Auth\Exception\TokenRevokedException;
use MonkeysLegion\Auth\Exception\AccountLockedException;
use MonkeysLegion\Auth\Exception\RateLimitException;
use MonkeysLegion\Auth\Exception\TwoFactorRequiredException;
use MonkeysLegion\Auth\Exception\TwoFactorInvalidException;
use MonkeysLegion\Auth\Exception\UnauthorizedException;
use MonkeysLegion\Auth\Exception\ForbiddenException;
use MonkeysLegion\Auth\Exception\UserAlreadyExistsException;
use MonkeysLegion\Auth\Tests\TestCase;

class ExceptionTest extends TestCase
{
    public function testAuthExceptionDefaults(): void
    {
        $e = new AuthException();

        $this->assertEquals('Authentication error', $e->getMessage());
        $this->assertEquals(401, $e->getCode());
        $this->assertEmpty($e->getContext());
    }

    public function testAuthExceptionWithContext(): void
    {
        $e = new AuthException('Custom message', 403, null, ['key' => 'value']);

        $this->assertEquals('Custom message', $e->getMessage());
        $this->assertEquals(403, $e->getCode());
        $this->assertEquals(['key' => 'value'], $e->getContext());
    }

    public function testAuthExceptionToArray(): void
    {
        $e = new AuthException('Test', 401, null, ['foo' => 'bar']);
        $array = $e->toArray();

        $this->assertTrue($array['error']);
        $this->assertEquals('Test', $array['message']);
        $this->assertEquals(401, $array['code']);
        $this->assertEquals(['foo' => 'bar'], $array['context']);
        $this->assertStringContainsString('AuthException', $array['type']);
    }

    public function testInvalidCredentialsException(): void
    {
        $e = new InvalidCredentialsException();

        $this->assertEquals('Invalid credentials', $e->getMessage());
        $this->assertEquals(401, $e->getCode());
    }

    public function testTokenExpiredException(): void
    {
        $e = new TokenExpiredException();

        $this->assertEquals('Token has expired', $e->getMessage());
        $this->assertEquals(401, $e->getCode());
    }

    public function testTokenInvalidException(): void
    {
        $e = new TokenInvalidException('Bad signature');

        $this->assertEquals('Bad signature', $e->getMessage());
        $this->assertEquals(401, $e->getCode());
    }

    public function testTokenRevokedException(): void
    {
        $e = new TokenRevokedException();

        $this->assertEquals('Token has been revoked', $e->getMessage());
        $this->assertEquals(401, $e->getCode());
    }

    public function testAccountLockedException(): void
    {
        $lockedUntil = time() + 900;
        $e = new AccountLockedException('Too many attempts', $lockedUntil);

        $this->assertEquals('Too many attempts', $e->getMessage());
        $this->assertEquals(423, $e->getCode());
        $this->assertEquals($lockedUntil, $e->getLockedUntil());
        $this->assertArrayHasKey('locked_until', $e->getContext());
    }

    public function testRateLimitException(): void
    {
        $e = new RateLimitException('Too many requests', 60);

        $this->assertEquals('Too many requests', $e->getMessage());
        $this->assertEquals(429, $e->getCode());
        $this->assertEquals(60, $e->getRetryAfter());
    }

    public function testTwoFactorRequiredException(): void
    {
        $e = new TwoFactorRequiredException('challenge-token-123');

        $this->assertEquals('Two-factor authentication required', $e->getMessage());
        $this->assertEquals(428, $e->getCode());
        $this->assertEquals('challenge-token-123', $e->getChallengeToken());
    }

    public function testTwoFactorInvalidException(): void
    {
        $e = new TwoFactorInvalidException();

        $this->assertEquals('Invalid two-factor code', $e->getMessage());
        $this->assertEquals(401, $e->getCode());
    }

    public function testUnauthorizedException(): void
    {
        $e = new UnauthorizedException('edit', 'Post');

        $this->assertEquals(403, $e->getCode());
        $this->assertEquals('edit', $e->getContext()['ability']);
        $this->assertEquals('Post', $e->getContext()['model']);
    }

    public function testForbiddenException(): void
    {
        $e = new ForbiddenException('Access denied');

        $this->assertEquals('Access denied', $e->getMessage());
        $this->assertEquals(403, $e->getCode());
    }

    public function testUserAlreadyExistsException(): void
    {
        $e = new UserAlreadyExistsException('Email taken');

        $this->assertEquals('Email taken', $e->getMessage());
        $this->assertEquals(409, $e->getCode());
    }

    public function testExceptionChaining(): void
    {
        $original = new \RuntimeException('Original error');
        $e = new AuthException('Wrapped', 500, $original);

        $this->assertSame($original, $e->getPrevious());
    }

    public function testWithContextCreatesClone(): void
    {
        $e1 = new AuthException('Test', 401, null, ['a' => 1]);
        $e2 = $e1->withContext(['b' => 2]);

        $this->assertEquals(['a' => 1], $e1->getContext());
        $this->assertEquals(['a' => 1, 'b' => 2], $e2->getContext());
        $this->assertNotSame($e1, $e2);
    }
}
