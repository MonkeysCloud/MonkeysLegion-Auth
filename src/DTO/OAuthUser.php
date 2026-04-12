<?php

declare(strict_types=1);

/**
 * MonkeysLegion Auth v2
 *
 * @package   MonkeysLegion\Auth
 * @author    MonkeysCloud <jorge@monkeys.cloud>
 * @license   MIT
 *
 * @requires  PHP 8.4
 */

namespace MonkeysLegion\Auth\DTO;

/**
 * OAuth user data — normalized across providers.
 *
 * SECURITY: The raw provider response is intentionally excluded from
 * toArray() to prevent accidental data leakage to clients.
 * Use getRaw() when you explicitly need provider-specific fields.
 */
final readonly class OAuthUser
{
    public function __construct(
        public string $providerId,
        public string $provider,
        public ?string $email = null,
        public ?string $name = null,
        public ?string $avatar = null,
        public ?string $nickname = null,
        /** @var array<string, mixed> Raw response data — never expose directly to clients */
        public array $raw = [],
    ) {}

    /**
     * Get the raw provider response.
     *
     * SECURITY: Only access this when you explicitly need provider-specific data.
     * Never forward this directly to clients or logs.
     *
     * @return array<string, mixed>
     */
    public function getRaw(): array
    {
        return $this->raw;
    }

    /**
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return [
            'provider_id' => $this->providerId,
            'provider'    => $this->provider,
            'email'       => $this->email,
            'name'        => $this->name,
            'avatar'      => $this->avatar,
            'nickname'    => $this->nickname,
            // raw is intentionally omitted to prevent data leakage
        ];
    }
}
