<?php

declare(strict_types=1);

/**
 * MonkeysLegion Auth v2
 *
 * @package   MonkeysLegion\Auth
 * @author    MonkeysCloud <jorge@monkeyscloud.com>
 * @license   MIT
 *
 * @requires  PHP 8.4
 */

namespace MonkeysLegion\Auth\TwoFactor;

use MonkeysLegion\Auth\Contract\TwoFactorProviderInterface;

/**
 * TOTP (Time-based One-Time Password) provider.
 *
 * SECURITY: Uses HMAC-SHA1 per RFC 6238. Allows ±1 time window.
 * Secrets use CSPRNG via random_bytes().
 */
final class TotpProvider implements TwoFactorProviderInterface
{
    private const int PERIOD = 30;
    private const int DIGITS = 6;
    private const int WINDOW = 1;

    public function generateSecret(int $length = 20): string
    {
        $bytes   = random_bytes($length);
        $base32  = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
        $encoded = '';

        $buffer    = 0;
        $bitsLeft  = 0;

        for ($i = 0; $i < strlen($bytes); $i++) {
            $buffer  = ($buffer << 8) | ord($bytes[$i]);
            $bitsLeft += 8;

            while ($bitsLeft >= 5) {
                $bitsLeft -= 5;
                $encoded  .= $base32[($buffer >> $bitsLeft) & 0x1f];
            }
        }

        if ($bitsLeft > 0) {
            $encoded .= $base32[($buffer << (5 - $bitsLeft)) & 0x1f];
        }

        return $encoded;
    }

    public function verify(string $secret, string $code): bool
    {
        $code = preg_replace('/\s+/', '', $code) ?? $code;

        if (strlen($code) !== self::DIGITS) {
            return false;
        }

        $timestamp = (int) floor(time() / self::PERIOD);

        for ($i = -self::WINDOW; $i <= self::WINDOW; $i++) {
            $expected = $this->generateCode($secret, $timestamp + $i);
            if (hash_equals($expected, $code)) {
                return true;
            }
        }

        return false;
    }

    public function getProvisioningUri(string $secret, string $email, string $issuer): string
    {
        $params = http_build_query([
            'secret' => $secret,
            'issuer' => $issuer,
            'digits' => self::DIGITS,
            'period' => self::PERIOD,
        ]);

        $label = rawurlencode($issuer) . ':' . rawurlencode($email);

        return "otpauth://totp/{$label}?{$params}";
    }

    public function generateBackupCodes(int $count = 8): array
    {
        $codes = [];
        for ($i = 0; $i < $count; $i++) {
            $codes[] = strtoupper(bin2hex(random_bytes(4)));
        }
        return $codes;
    }

    private function generateCode(string $secret, int $counter): string
    {
        $secretBytes = $this->base32Decode($secret);
        $counterBytes = pack('N*', 0, $counter);

        $hash  = hash_hmac('sha1', $counterBytes, $secretBytes, true);
        $offset = ord($hash[19]) & 0x0f;

        $code = (
            ((ord($hash[$offset])     & 0x7f) << 24) |
            ((ord($hash[$offset + 1]) & 0xff) << 16) |
            ((ord($hash[$offset + 2]) & 0xff) << 8)  |
            (ord($hash[$offset + 3])  & 0xff)
        ) % (10 ** self::DIGITS);

        return str_pad((string) $code, self::DIGITS, '0', STR_PAD_LEFT);
    }

    private function base32Decode(string $encoded): string
    {
        $chars  = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
        $buffer = 0;
        $bits   = 0;
        $output = '';

        for ($i = 0, $len = strlen($encoded); $i < $len; $i++) {
            $val = strpos($chars, strtoupper($encoded[$i]));
            if ($val === false) {
                continue;
            }
            $buffer = ($buffer << 5) | $val;
            $bits  += 5;

            if ($bits >= 8) {
                $bits -= 8;
                $output .= chr(($buffer >> $bits) & 0xff);
            }
        }

        return $output;
    }
}
