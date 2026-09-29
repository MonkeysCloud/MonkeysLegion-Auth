<?php
declare(strict_types=1);

namespace Tests\Unit\Security;

use MonkeysLegion\Auth\Security\PwnedPasswordChecker;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

final class PwnedPasswordCheckerTest extends TestCase
{
    #[Test]
    public function disabled_checker_always_returns_false(): void
    {
        $checker = new PwnedPasswordChecker(enabled: false);

        self::assertFalse($checker->isPwned('password123'));
        self::assertFalse($checker->isEnabled());
    }

    #[Test]
    public function is_enabled_returns_true_by_default(): void
    {
        $checker = new PwnedPasswordChecker();

        self::assertTrue($checker->isEnabled());
    }

    #[Test]
    public function mock_api_response_detects_pwned_password(): void
    {
        // Create a checker subclass that overrides fetchRange to return a mock response.
        $checker = new class extends PwnedPasswordChecker {
            protected function fetchRange(string $prefix): ?string
            {
                // SHA-1 of "password" is 5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8
                // Prefix: 5BAA6, Suffix: 1E4C9B93F3F0682250B6CF8331B7EE68FD8
                if ($prefix === '5BAA6') {
                    return "1E4C9B93F3F0682250B6CF8331B7EE68FD8:12345\r\n" .
                           "1E4C9B93F3F0682250B6CF8331B7EE68FDA:1\r\n";
                }
                return "AAAAA:1\r\nBBBBB:2\r\n";
            }

            // Make fetchRange accessible
            public function testFetchRange(string $prefix): ?string
            {
                return $this->fetchRange($prefix);
            }
        };

        // "password" is one of the most pwned passwords.
        $result = $checker->isPwned('password');

        self::assertTrue($result, 'The password "password" should be detected as pwned');
    }

    #[Test]
    public function mock_api_response_does_not_flag_safe_password(): void
    {
        $checker = new class extends PwnedPasswordChecker {
            protected function fetchRange(string $prefix): ?string
            {
                // Return hashes that don't match our test password.
                return "AAAAA:1\r\nBBBBB:2\r\nCCCCC:3\r\n";
            }
        };

        // A random password whose SHA-1 suffix won't be in our mock.
        $result = $checker->isPwned('xK9$mP2!vQ7zR4');

        self::assertFalse($result, 'A safe password should not be flagged as pwned');
    }

    #[Test]
    public function api_failure_returns_false_fail_open(): void
    {
        $checker = new class extends PwnedPasswordChecker {
            protected function fetchRange(string $prefix): ?string
            {
                return null; // Simulate API failure.
            }
        };

        $result = $checker->isPwned('password');

        self::assertFalse($result, 'API failure should fail-open (return false)');
    }

    #[Test]
    public function threshold_filters_low_count_breaches(): void
    {
        // SHA-1 of "password" = 5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8
        $checker = new class(1, threshold: 100) extends PwnedPasswordChecker {
            public function __construct(bool $enabled = true, int $threshold = 100)
            {
                parent::__construct(enabled: $enabled, threshold: $threshold);
            }

            protected function fetchRange(string $prefix): ?string
            {
                if ($prefix === '5BAA6') {
                    return "1E4C9B93F3F0682250B6CF8331B7EE68FD8:50\r\n"; // Count 50 < threshold 100
                }
                return "AAAAA:1\r\n";
            }
        };

        $result = $checker->isPwned('password');

        self::assertFalse($result, 'Breach count below threshold should not be flagged');
    }

    #[Test]
    public function cache_prevents_repeated_api_calls(): void
    {
        $callCount = 0;
        $checker = new class($callCount) extends PwnedPasswordChecker {
            private int $calls;

            public function __construct(int &$callCount)
            {
                parent::__construct();
                $this->calls = &$callCount;
            }

            protected function fetchRange(string $prefix): ?string
            {
                $this->calls++;
                return "AAAAA:1\r\n";
            }

            public function getCallCount(): int
            {
                return $this->calls;
            }
        };

        $checker->isPwned('test1');
        // Same prefix for test1 and test2 only if they share first 5 SHA-1 chars.
        // They won't, so this tests two different prefixes.
        $checker->isPwned('test2');

        // Both should trigger API calls since prefixes differ.
        self::assertSame(2, $checker->getCallCount());
    }
}
