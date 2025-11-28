<?php

declare(strict_types=1);

namespace MonkeysLegion\Auth\Tests\Unit\TwoFactor;

use MonkeysLegion\Auth\TwoFactor\TotpProvider;
use MonkeysLegion\Auth\Tests\TestCase;

class TotpProviderTest extends TestCase
{
    private TotpProvider $totp;

    protected function setUp(): void
    {
        parent::setUp();
        $this->totp = new TotpProvider();
    }

    public function testGenerateSecretReturnsBase32String(): void
    {
        $secret = $this->totp->generateSecret();

        $this->assertIsString($secret);
        $this->assertNotEmpty($secret);
        // Base32 characters only
        $this->assertMatchesRegularExpression('/^[A-Z2-7]+$/', $secret);
    }

    public function testGenerateSecretIsUnique(): void
    {
        $secret1 = $this->totp->generateSecret();
        $secret2 = $this->totp->generateSecret();

        $this->assertNotEquals($secret1, $secret2);
    }

    public function testGetProvisioningUriFormat(): void
    {
        $secret = 'JBSWY3DPEHPK3PXP';
        $email = 'test@example.com';
        $issuer = 'MyApp';

        $uri = $this->totp->getProvisioningUri($secret, $email, $issuer);

        $this->assertStringStartsWith('otpauth://totp/', $uri);
        $this->assertStringContainsString('secret=' . $secret, $uri);
        $this->assertStringContainsString('issuer=MyApp', $uri);
        $this->assertStringContainsString(urlencode($email), $uri);
    }

    public function testVerifyValidCode(): void
    {
        $secret = $this->totp->generateSecret();
        
        // Generate current code
        $code = $this->generateTotpCode($secret);

        $this->assertTrue($this->totp->verify($secret, $code));
    }

    public function testVerifyInvalidCode(): void
    {
        $secret = $this->totp->generateSecret();

        $this->assertFalse($this->totp->verify($secret, '000000'));
        $this->assertFalse($this->totp->verify($secret, '999999'));
        $this->assertFalse($this->totp->verify($secret, 'abcdef'));
    }

    public function testVerifyCodeWithWhitespace(): void
    {
        $secret = $this->totp->generateSecret();
        $code = $this->generateTotpCode($secret);

        // Add whitespace
        $codeWithSpaces = substr($code, 0, 3) . ' ' . substr($code, 3);

        $this->assertTrue($this->totp->verify($secret, $codeWithSpaces));
    }

    public function testVerifyRejectsWrongLengthCode(): void
    {
        $secret = $this->totp->generateSecret();

        $this->assertFalse($this->totp->verify($secret, '12345'));
        $this->assertFalse($this->totp->verify($secret, '1234567'));
        $this->assertFalse($this->totp->verify($secret, ''));
    }

    public function testGenerateBackupCodes(): void
    {
        $codes = $this->totp->generateBackupCodes(8);

        $this->assertCount(8, $codes);
        
        foreach ($codes as $code) {
            $this->assertIsString($code);
            $this->assertEquals(8, strlen($code));
            // Should be hex characters
            $this->assertMatchesRegularExpression('/^[A-F0-9]+$/', $code);
        }
    }

    public function testGenerateBackupCodesAreUnique(): void
    {
        $codes = $this->totp->generateBackupCodes(10);

        $uniqueCodes = array_unique($codes);
        $this->assertCount(10, $uniqueCodes);
    }

    public function testHashBackupCode(): void
    {
        $code = 'ABC12345';
        $hash = $this->totp->hashBackupCode($code);

        $this->assertIsString($hash);
        $this->assertNotEquals($code, $hash);
        // Should be a password hash
        $this->assertTrue(password_verify(strtoupper($code), $hash));
    }

    public function testVerifyBackupCodeValid(): void
    {
        $codes = ['CODE1234', 'CODE5678', 'CODE9ABC'];
        $hashes = array_map(fn($c) => $this->totp->hashBackupCode($c), $codes);

        $result = $this->totp->verifyBackupCode('CODE5678', $hashes);

        $this->assertEquals(1, $result);
    }

    public function testVerifyBackupCodeInvalid(): void
    {
        $codes = ['CODE1234', 'CODE5678'];
        $hashes = array_map(fn($c) => $this->totp->hashBackupCode($c), $codes);

        $result = $this->totp->verifyBackupCode('WRONGCODE', $hashes);

        $this->assertFalse($result);
    }

    public function testVerifyBackupCodeCaseInsensitive(): void
    {
        $hash = $this->totp->hashBackupCode('ABC12345');

        $result1 = $this->totp->verifyBackupCode('ABC12345', [$hash]);
        $result2 = $this->totp->verifyBackupCode('abc12345', [$hash]);

        $this->assertEquals(0, $result1);
        $this->assertEquals(0, $result2);
    }

    public function testVerifyBackupCodeWithWhitespace(): void
    {
        $hash = $this->totp->hashBackupCode('ABC12345');

        $result = $this->totp->verifyBackupCode('ABC 123 45', [$hash]);

        $this->assertEquals(0, $result);
    }

    /**
     * Helper to generate a valid TOTP code for testing.
     * This mirrors the internal implementation.
     */
    private function generateTotpCode(string $secret): string
    {
        $timeStep = (int) floor(time() / 30);
        $secretBytes = $this->base32Decode($secret);
        $time = pack('J', $timeStep);
        $hash = hash_hmac('sha1', $time, $secretBytes, true);
        
        $offset = ord($hash[19]) & 0x0F;
        $code = (
            ((ord($hash[$offset]) & 0x7F) << 24) |
            ((ord($hash[$offset + 1]) & 0xFF) << 16) |
            ((ord($hash[$offset + 2]) & 0xFF) << 8) |
            (ord($hash[$offset + 3]) & 0xFF)
        ) % 1000000;

        return str_pad((string) $code, 6, '0', STR_PAD_LEFT);
    }

    private function base32Decode(string $data): string
    {
        $alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
        $data = strtoupper($data);
        $binary = '';

        foreach (str_split($data) as $char) {
            $pos = strpos($alphabet, $char);
            if ($pos === false) continue;
            $binary .= str_pad(decbin($pos), 5, '0', STR_PAD_LEFT);
        }

        $result = '';
        foreach (str_split($binary, 8) as $chunk) {
            if (strlen($chunk) === 8) {
                $result .= chr(bindec($chunk));
            }
        }

        return $result;
    }
}
