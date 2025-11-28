<?php

declare(strict_types=1);

namespace MonkeysLegion\Auth\Tests\Unit\RateLimit;

use MonkeysLegion\Auth\RateLimit\InMemoryRateLimiter;
use MonkeysLegion\Auth\Tests\TestCase;

class InMemoryRateLimiterTest extends TestCase
{
    private InMemoryRateLimiter $limiter;

    protected function setUp(): void
    {
        parent::setUp();
        $this->limiter = new InMemoryRateLimiter();
    }

    public function testAttemptAllowsWithinLimit(): void
    {
        $key = 'test-key';

        $this->assertTrue($this->limiter->attempt($key, 5, 60));
        $this->assertTrue($this->limiter->attempt($key, 5, 60));
        $this->assertTrue($this->limiter->attempt($key, 5, 60));
    }

    public function testAttemptBlocksAfterLimit(): void
    {
        $key = 'test-key';

        // Use up all attempts
        for ($i = 0; $i < 5; $i++) {
            $this->assertTrue($this->limiter->attempt($key, 5, 60));
        }

        // Next attempt should fail
        $this->assertFalse($this->limiter->attempt($key, 5, 60));
    }

    public function testRemainingReturnsCorrectCount(): void
    {
        $key = 'test-key';

        $this->assertEquals(5, $this->limiter->remaining($key, 5));

        $this->limiter->hit($key, 60);
        $this->assertEquals(4, $this->limiter->remaining($key, 5));

        $this->limiter->hit($key, 60);
        $this->limiter->hit($key, 60);
        $this->assertEquals(2, $this->limiter->remaining($key, 5));
    }

    public function testHitIncrementsCounter(): void
    {
        $key = 'test-key';

        $count1 = $this->limiter->hit($key, 60);
        $count2 = $this->limiter->hit($key, 60);
        $count3 = $this->limiter->hit($key, 60);

        $this->assertEquals(1, $count1);
        $this->assertEquals(2, $count2);
        $this->assertEquals(3, $count3);
    }

    public function testClearResetsCounter(): void
    {
        $key = 'test-key';

        $this->limiter->hit($key, 60);
        $this->limiter->hit($key, 60);
        $this->assertEquals(3, $this->limiter->remaining($key, 5));

        $this->limiter->clear($key);

        $this->assertEquals(5, $this->limiter->remaining($key, 5));
    }

    public function testTooManyAttemptsReturnsTrueWhenLimitReached(): void
    {
        $key = 'test-key';

        $this->assertFalse($this->limiter->tooManyAttempts($key, 3));

        $this->limiter->hit($key, 60);
        $this->limiter->hit($key, 60);
        $this->limiter->hit($key, 60);

        $this->assertTrue($this->limiter->tooManyAttempts($key, 3));
    }

    public function testRetryAfterReturnsPositiveValue(): void
    {
        $key = 'test-key';

        $this->limiter->hit($key, 60);

        $retryAfter = $this->limiter->retryAfter($key);

        $this->assertGreaterThan(0, $retryAfter);
        $this->assertLessThanOrEqual(60, $retryAfter);
    }

    public function testRetryAfterReturnsZeroForNewKey(): void
    {
        $this->assertEquals(0, $this->limiter->retryAfter('new-key'));
    }

    public function testDifferentKeysAreIndependent(): void
    {
        $this->limiter->hit('key1', 60);
        $this->limiter->hit('key1', 60);
        $this->limiter->hit('key2', 60);

        $this->assertEquals(3, $this->limiter->remaining('key1', 5));
        $this->assertEquals(4, $this->limiter->remaining('key2', 5));
    }

    public function testExpiredEntriesAreCleared(): void
    {
        $key = 'test-key';

        // Hit with 1 second decay
        $this->limiter->hit($key, 1);
        $this->assertEquals(4, $this->limiter->remaining($key, 5));

        // Wait for expiry
        sleep(2);

        // Should be reset
        $this->assertEquals(5, $this->limiter->remaining($key, 5));
    }

    public function testAvailableInReturnsSeconds(): void
    {
        $key = 'test-key';

        $this->limiter->hit($key, 120);

        $availableIn = $this->limiter->availableIn($key);

        $this->assertGreaterThan(110, $availableIn);
        $this->assertLessThanOrEqual(120, $availableIn);
    }
}
