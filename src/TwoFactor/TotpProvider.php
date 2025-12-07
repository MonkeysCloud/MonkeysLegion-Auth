<?php

declare(strict_types=1);

namespace MonkeysLegion\Auth\TwoFactor;

use MonkeysLegion\Auth\Contract\TwoFactorProviderInterface;

/**
 * TOTP (Time-based One-Time Password) provider for 2FA.
 * 
 * Compatible with Google Authenticator, Authy, 1Password, etc.
 */
final class TotpProvider implements TwoFactorProviderInterface
{
    private const SECRET_LENGTH = 20;
    private const CODE_LENGTH = 6;
    private const TIME_STEP = 30;
    private const WINDOW = 1;

    private const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

    public function generateSecret(): string
    {
        $bytes = random_bytes(self::SECRET_LENGTH);
        return $this->base32Encode($bytes);
    }

    public function getProvisioningUri(string $secret, string $email, string $issuer): string
    {
        $params = http_build_query([
            'secret' => $secret,
            'issuer' => $issuer,
            'algorithm' => 'SHA1',
            'digits' => self::CODE_LENGTH,
            'period' => self::TIME_STEP,
        ]);

        $label = rawurlencode($issuer) . ':' . rawurlencode($email);
        return "otpauth://totp/{$label}?{$params}";
    }

    public function getQrCodeUri(string $uri): string
    {
        return 'https://api.qrserver.com/v1/create-qr-code/?size=200x200&data=' . rawurlencode($uri);
    }

    public function verify(string $secret, string $code): bool
    {
        $code = preg_replace('/\s+/', '', $code);

        if (strlen($code) !== self::CODE_LENGTH || !ctype_digit($code)) {
            return false;
        }

        $currentTime = time();
        $timeStep = (int) floor($currentTime / self::TIME_STEP);

        for ($offset = -self::WINDOW; $offset <= self::WINDOW; $offset++) {
            $expected = $this->generateCode($secret, $timeStep + $offset);
            if (hash_equals($expected, $code)) {
                return true;
            }
        }

        return false;
    }

    public function generateBackupCodes(int $count = 8): array
    {
        $codes = [];
        for ($i = 0; $i < $count; $i++) {
            $codes[] = strtoupper(bin2hex(random_bytes(4)));
        }
        return $codes;
    }

    public function generateRecoveryCodes(int $count = 8): array
    {
        return $this->generateBackupCodes($count);
    }

    public function hashBackupCode(string $code): string
    {
        return password_hash(strtoupper($code), PASSWORD_DEFAULT);
    }

    public function verifyBackupCode(string $code, array $hashes): int|false
    {
        $code = strtoupper(preg_replace('/\s+/', '', $code));

        foreach ($hashes as $index => $hash) {
            if (password_verify($code, $hash)) {
                return $index;
            }
        }

        return false;
    }

    private function generateCode(string $secret, int $timeStep): string
    {
        $secretBytes = $this->base32Decode($secret);

        // Pack time into 64-bit big-endian binary string (RFC 4226/6238 requirement)
        // usage of pack('J') depends on PHP version/architecture, so we manually pack
        // high and low 32-bit words to ensure correct byte order on all systems.
        $time = pack('N', $timeStep >> 32) . pack('N', $timeStep & 0xFFFFFFFF);

        $hash = hash_hmac('sha1', $time, $secretBytes, true);

        $offset = ord($hash[19]) & 0x0F;
        $code = (
            ((ord($hash[$offset]) & 0x7F) << 24) |
            ((ord($hash[$offset + 1]) & 0xFF) << 16) |
            ((ord($hash[$offset + 2]) & 0xFF) << 8) |
            (ord($hash[$offset + 3]) & 0xFF)
        ) % (10 ** self::CODE_LENGTH);

        return str_pad((string) $code, self::CODE_LENGTH, '0', STR_PAD_LEFT);
    }

    private function base32Encode(string $data): string
    {
        $binary = '';
        foreach (str_split($data) as $char) {
            $binary .= str_pad(decbin(ord($char)), 8, '0', STR_PAD_LEFT);
        }

        $result = '';
        foreach (str_split($binary, 5) as $chunk) {
            $chunk = str_pad($chunk, 5, '0', STR_PAD_RIGHT);
            $result .= self::BASE32_ALPHABET[bindec($chunk)];
        }

        return $result;
    }

    private function base32Decode(string $data): string
    {
        $data = strtoupper($data);
        $binary = '';

        foreach (str_split($data) as $char) {
            $pos = strpos(self::BASE32_ALPHABET, $char);
            if ($pos === false) {
                continue;
            }
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
