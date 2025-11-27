<?php

declare(strict_types=1);

namespace MonkeysLegion\Auth\DTO;

/**
 * Data transfer object for OAuth user information.
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
        public array $raw = [],
    ) {}

    public function toArray(): array
    {
        return [
            'provider_id' => $this->providerId,
            'provider' => $this->provider,
            'email' => $this->email,
            'name' => $this->name,
            'avatar' => $this->avatar,
            'nickname' => $this->nickname,
            'raw' => $this->raw,
        ];
    }
}
