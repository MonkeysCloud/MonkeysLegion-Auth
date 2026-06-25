<?php

declare(strict_types=1);

namespace MonkeysLegion\Auth\Tests\Fixtures;

use Psr\Http\Message\UriInterface;

class FakePsr7Uri implements UriInterface
{
    public function __construct(private string $path = '/') {}
    public function getScheme(): string { return 'https'; }
    public function getAuthority(): string { return 'localhost'; }
    public function getUserInfo(): string { return ''; }
    public function getHost(): string { return 'localhost'; }
    public function getPort(): ?int { return null; }
    public function getPath(): string { return $this->path; }
    public function getQuery(): string { return ''; }
    public function getFragment(): string { return ''; }
    public function withScheme(string $scheme): static { return $this; }
    public function withUserInfo(string $user, ?string $password = null): static { return $this; }
    public function withHost(string $host): static { return $this; }
    public function withPort(?int $port): static { return $this; }
    public function withPath(string $path): static { $c = clone $this; $c->path = $path; return $c; }
    public function withQuery(string $query): static { return $this; }
    public function withFragment(string $fragment): static { return $this; }
    public function __toString(): string { return $this->path; }
}
