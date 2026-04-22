<?php

declare(strict_types=1);

namespace MonkeysLegion\Auth\Tests\Fixtures;

use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Message\StreamInterface;
use Psr\Http\Message\UriInterface;

class FakePsr7Request implements ServerRequestInterface
{
    private array $headers = [];
    private array $attributes = [];
    private array $queryParams = [];

    public function __construct(private string $method = 'GET', private ?UriInterface $uri = null)
    {
        $this->uri ??= new FakePsr7Uri();
    }

    public function getProtocolVersion(): string { return '1.1'; }
    public function withProtocolVersion(string $version): static { return $this; }
    public function getHeaders(): array { return $this->headers; }
    public function hasHeader(string $name): bool { return isset($this->headers[$name]); }
    public function getHeader(string $name): array { return $this->headers[$name] ?? []; }
    public function getHeaderLine(string $name): string { return implode(', ', $this->headers[$name] ?? []); }

    public function withHeader(string $name, $value): static
    {
        $c = clone $this;
        $c->headers[$name] = is_array($value) ? $value : [$value];
        return $c;
    }

    public function withAddedHeader(string $name, $value): static { return $this->withHeader($name, $value); }
    public function withoutHeader(string $name): static { $c = clone $this; unset($c->headers[$name]); return $c; }
    public function getBody(): StreamInterface { return new FakePsr7Stream(); }
    public function withBody(StreamInterface $body): static { return $this; }
    public function getRequestTarget(): string { return $this->uri->getPath(); }
    public function withRequestTarget(string $requestTarget): static { return $this; }
    public function getMethod(): string { return $this->method; }
    public function withMethod(string $method): static { $c = clone $this; $c->method = $method; return $c; }
    public function getUri(): UriInterface { return $this->uri; }
    public function withUri(UriInterface $uri, bool $preserveHost = false): static { $c = clone $this; $c->uri = $uri; return $c; }
    public function getServerParams(): array { return []; }
    public function getCookieParams(): array { return []; }
    public function withCookieParams(array $cookies): static { return $this; }
    public function getQueryParams(): array { return $this->queryParams; }
    public function withQueryParams(array $query): static { $c = clone $this; $c->queryParams = $query; return $c; }
    public function getUploadedFiles(): array { return []; }
    public function withUploadedFiles(array $uploadedFiles): static { return $this; }
    public function getParsedBody(): mixed { return null; }
    public function withParsedBody($data): static { return $this; }
    public function getAttributes(): array { return $this->attributes; }
    public function getAttribute(string $name, $default = null): mixed { return $this->attributes[$name] ?? $default; }
    public function withAttribute(string $name, $value): static { $c = clone $this; $c->attributes[$name] = $value; return $c; }
    public function withoutAttribute(string $name): static { $c = clone $this; unset($c->attributes[$name]); return $c; }
}
