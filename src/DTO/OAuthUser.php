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

namespace MonkeysLegion\Auth\DTO;

/**
 * OAuth user data — normalized across providers.
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
        /** @var array<string, mixed> Raw response data */
        public array $raw = [],
    ) {}

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
        ];
    }
}
