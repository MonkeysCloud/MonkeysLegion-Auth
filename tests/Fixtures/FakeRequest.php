<?php

declare(strict_types=1);

namespace MonkeysLegion\Auth\Tests\Fixtures;

use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Message\UriInterface;
use Psr\Http\Message\StreamInterface;

/**
 * Simple fake PSR-7 request for testing middleware.
 */
class FakeRequest implements ServerRequestInterface
{
    private array $headers = [];
    private array $attributes = [];
    private array $queryParams = [];
    private array $cookieParams = [];
    private array $serverParams = [];
    private string $method = 'GET';
    private string $path = '/';

    public function __construct(
        string $method = 'GET',
        string $path = '/',
        array $headers = [],
        array $attributes = [],
    ) {
        $this->method = $method;
        $this->path = $path;
        $this->headers = $headers;
        $this->attributes = $attributes;
    }

    public static function create(
        string $method = 'GET',
        string $path = '/',
        ?string $bearerToken = null,
    ): self {
        $headers = [];
        if ($bearerToken !== null) {
            $headers['Authorization'] = ['Bearer ' . $bearerToken];
        }
        return new self($method, $path, $headers);
    }

    public function getProtocolVersion(): string
    {
        return '1.1';
    }

    public function withProtocolVersion(string $version): static
    {
        $clone = clone $this;
        return $clone;
    }

    public function getHeaders(): array
    {
        return $this->headers;
    }

    public function hasHeader(string $name): bool
    {
        return isset($this->headers[strtolower($name)]) || isset($this->headers[$name]);
    }

    public function getHeader(string $name): array
    {
        return $this->headers[$name] ?? $this->headers[strtolower($name)] ?? [];
    }

    public function getHeaderLine(string $name): string
    {
        $values = $this->getHeader($name);
        return implode(', ', $values);
    }

    public function withHeader(string $name, $value): static
    {
        $clone = clone $this;
        $clone->headers[$name] = is_array($value) ? $value : [$value];
        return $clone;
    }

    public function withAddedHeader(string $name, $value): static
    {
        $clone = clone $this;
        $existing = $clone->headers[$name] ?? [];
        $clone->headers[$name] = array_merge($existing, is_array($value) ? $value : [$value]);
        return $clone;
    }

    public function withoutHeader(string $name): static
    {
        $clone = clone $this;
        unset($clone->headers[$name]);
        return $clone;
    }

    public function getBody(): StreamInterface
    {
        throw new \RuntimeException('Not implemented');
    }

    public function withBody(StreamInterface $body): static
    {
        return clone $this;
    }

    public function getRequestTarget(): string
    {
        return $this->path;
    }

    public function withRequestTarget(string $requestTarget): static
    {
        $clone = clone $this;
        $clone->path = $requestTarget;
        return $clone;
    }

    public function getMethod(): string
    {
        return $this->method;
    }

    public function withMethod(string $method): static
    {
        $clone = clone $this;
        $clone->method = $method;
        return $clone;
    }

    public function getUri(): UriInterface
    {
        return new class($this->path) implements UriInterface {
            public function __construct(private string $path) {}
            public function getScheme(): string { return 'https'; }
            public function getAuthority(): string { return 'example.com'; }
            public function getUserInfo(): string { return ''; }
            public function getHost(): string { return 'example.com'; }
            public function getPort(): ?int { return null; }
            public function getPath(): string { return $this->path; }
            public function getQuery(): string { return ''; }
            public function getFragment(): string { return ''; }
            public function withScheme(string $scheme): static { return clone $this; }
            public function withUserInfo(string $user, ?string $password = null): static { return clone $this; }
            public function withHost(string $host): static { return clone $this; }
            public function withPort(?int $port): static { return clone $this; }
            public function withPath(string $path): static { $c = clone $this; $c->path = $path; return $c; }
            public function withQuery(string $query): static { return clone $this; }
            public function withFragment(string $fragment): static { return clone $this; }
            public function __toString(): string { return 'https://example.com' . $this->path; }
        };
    }

    public function withUri(UriInterface $uri, bool $preserveHost = false): static
    {
        $clone = clone $this;
        $clone->path = $uri->getPath();
        return $clone;
    }

    public function getServerParams(): array
    {
        return $this->serverParams;
    }

    public function getCookieParams(): array
    {
        return $this->cookieParams;
    }

    public function withCookieParams(array $cookies): static
    {
        $clone = clone $this;
        $clone->cookieParams = $cookies;
        return $clone;
    }

    public function getQueryParams(): array
    {
        return $this->queryParams;
    }

    public function withQueryParams(array $query): static
    {
        $clone = clone $this;
        $clone->queryParams = $query;
        return $clone;
    }

    public function getUploadedFiles(): array
    {
        return [];
    }

    public function withUploadedFiles(array $uploadedFiles): static
    {
        return clone $this;
    }

    public function getParsedBody()
    {
        return null;
    }

    public function withParsedBody($data): static
    {
        return clone $this;
    }

    public function getAttributes(): array
    {
        return $this->attributes;
    }

    public function getAttribute(string $name, $default = null): mixed
    {
        return $this->attributes[$name] ?? $default;
    }

    public function withAttribute(string $name, $value): static
    {
        $clone = clone $this;
        $clone->attributes[$name] = $value;
        return $clone;
    }

    public function withoutAttribute(string $name): static
    {
        $clone = clone $this;
        unset($clone->attributes[$name]);
        return $clone;
    }

    public function withServerParams(array $params): static
    {
        $clone = clone $this;
        $clone->serverParams = $params;
        return $clone;
    }
}
