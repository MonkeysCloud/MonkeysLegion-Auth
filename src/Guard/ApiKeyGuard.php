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

namespace MonkeysLegion\Auth\Guard;

use MonkeysLegion\Auth\Contract\AuthenticatableInterface;
use MonkeysLegion\Auth\Contract\GuardInterface;
use MonkeysLegion\Auth\Contract\UserProviderInterface;
use Psr\Http\Message\ServerRequestInterface;

/**
 * API key guard — validates X-API-Key header or query parameter.
 *
 * SECURITY: Keys are compared using hash_equals to prevent timing attacks.
 */
final class ApiKeyGuard implements GuardInterface
{
    private ?AuthenticatableInterface $_user = null;

    public function __construct(
        private readonly UserProviderInterface $users,
        private readonly string $headerName = 'X-API-Key',
        private readonly ?string $queryParam = null,
    ) {}

    public function name(): string
    {
        return 'api-key';
    }

    public function authenticate(ServerRequestInterface $request): ?AuthenticatableInterface
    {
        $key = $this->extractApiKey($request);
        if ($key === null) {
            return null;
        }

        $user = $this->users->findByApiKey($key);
        if ($user !== null) {
            $this->_user = $user;
        }

        return $user;
    }

    public function validate(array $credentials): bool
    {
        $key = $credentials['api_key'] ?? null;
        if (!is_string($key)) {
            return false;
        }

        return $this->users->findByApiKey($key) !== null;
    }

    public function user(): ?AuthenticatableInterface
    {
        return $this->_user;
    }

    public function id(): int|string|null
    {
        return $this->_user?->getAuthIdentifier();
    }

    public function check(): bool
    {
        return $this->_user !== null;
    }

    public function guest(): bool
    {
        return $this->_user === null;
    }

    private function extractApiKey(ServerRequestInterface $request): ?string
    {
        // Check header first
        $key = $request->getHeaderLine($this->headerName);
        if ($key !== '') {
            return $key;
        }

        // Check query parameter as fallback
        if ($this->queryParam !== null) {
            $params = $request->getQueryParams();
            $key    = $params[$this->queryParam] ?? '';
            if (is_string($key) && $key !== '') {
                return $key;
            }
        }

        return null;
    }
}
