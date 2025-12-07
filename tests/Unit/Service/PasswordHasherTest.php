<?php

declare(strict_types=1);

namespace MonkeysLegion\Auth\Tests\Unit\Service;

use MonkeysLegion\Auth\Service\PasswordHasher;
use MonkeysLegion\Auth\Tests\TestCase;

class PasswordHasherTest extends TestCase
{
    private PasswordHasher $hasher;

    protected function setUp(): void
    {
        parent::setUp();
        $this->hasher = new PasswordHasher();
    }

    public function testHashReturnsString(): void
    {
        $hash = $this->hasher->hash('password123');

        $this->assertIsString($hash);
        $this->assertNotEmpty($hash);
        $this->assertNotEquals('password123', $hash);
    }

    public function testHashIsDifferentEachTime(): void
    {
        $hash1 = $this->hasher->hash('password123');
        $hash2 = $this->hasher->hash('password123');

        $this->assertNotEquals($hash1, $hash2);
    }

    public function testVerifyCorrectPassword(): void
    {
        $hash = $this->hasher->hash('password123');

        $this->assertTrue($this->hasher->verify('password123', $hash));
    }

    public function testVerifyIncorrectPassword(): void
    {
        $hash = $this->hasher->hash('password123');

        $this->assertFalse($this->hasher->verify('wrongpassword', $hash));
    }

    public function testVerifyEmptyPassword(): void
    {
        $hash = $this->hasher->hash('password123');

        $this->assertFalse($this->hasher->verify('', $hash));
    }

    public function testVerifyEmptyHash(): void
    {
        $this->assertFalse($this->hasher->verify('password123', ''));
    }

    public function testNeedsRehashReturnsFalseForFreshHash(): void
    {
        $hash = $this->hasher->hash('password123');

        $this->assertFalse($this->hasher->needsRehash($hash));
    }

    public function testNeedsRehashReturnsTrueForOldAlgorithm(): void
    {
        // MD5 hash (old algorithm)
        $oldHash = md5('password123');

        $this->assertTrue($this->hasher->needsRehash($oldHash));
    }

    public function testNeedsRehashReturnsTrueForWeakBcrypt(): void
    {
        // Bcrypt with cost 4 (weak)
        $weakHash = password_hash('password123', PASSWORD_BCRYPT, ['cost' => 4]);

        // Default cost is 12, so this should need rehash
        $this->assertTrue($this->hasher->needsRehash($weakHash));
    }

    public function testHashWithDifferentCost(): void
    {
        $hasher = new PasswordHasher(cost: 10);
        $hash = $hasher->hash('password123');

        $this->assertTrue($hasher->verify('password123', $hash));
    }

    public function testHashWithArgon2(): void
    {
        if (!defined('PASSWORD_ARGON2ID')) {
            $this->markTestSkipped('Argon2 not available');
        }

        $hasher = new PasswordHasher(algorithm: PASSWORD_ARGON2ID);
        $hash = $hasher->hash('password123');

        $this->assertTrue($hasher->verify('password123', $hash));
        $this->assertStringStartsWith('$argon2id$', $hash);
    }

    public function testHashWithSpecialCharacters(): void
    {
        $password = 'p@$$w0rd!#$%^&*()_+{}[]|\\:";\'<>?,./`~';
        $hash = $this->hasher->hash($password);

        $this->assertTrue($this->hasher->verify($password, $hash));
    }

    public function testHashWithUnicodeCharacters(): void
    {
        $password = 'пароль密码كلمة السر🔐';
        $hash = $this->hasher->hash($password);

        $this->assertTrue($this->hasher->verify($password, $hash));
    }

    public function testHashWithLongPassword(): void
    {
        $password = str_repeat('a', 1000);
        $hash = $this->hasher->hash($password);

        $this->assertTrue($this->hasher->verify($password, $hash));
    }

    public function testVerifyCaseSensitive(): void
    {
        $hash = $this->hasher->hash('Password123');

        $this->assertTrue($this->hasher->verify('Password123', $hash));
        $this->assertFalse($this->hasher->verify('password123', $hash));
        $this->assertFalse($this->hasher->verify('PASSWORD123', $hash));
    }
}
