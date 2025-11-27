<?php

declare(strict_types=1);

namespace MonkeysLegion\Auth\Tests\Unit\Middleware;

use MonkeysLegion\Auth\Middleware\AuthenticationMiddleware;
use MonkeysLegion\Auth\Service\AuthService;
use MonkeysLegion\Auth\Service\JwtService;
use MonkeysLegion\Auth\Service\PasswordHasher;
use MonkeysLegion\Auth\Tests\TestCase;
use MonkeysLegion\Auth\Tests\Fixtures\FakeUser;
use MonkeysLegion\Auth\Tests\Fixtures\FakeUserProvider;
use MonkeysLegion\Auth\Tests\Fixtures\FakeTokenStorage;
use MonkeysLegion\Auth\Tests\Fixtures\FakeRequest;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;
use MonkeysLegion\Auth\Tests\Fixtures\FakeResponse;

class AuthenticationMiddlewareTest extends TestCase
{
    private AuthenticationMiddleware $middleware;
    private AuthService $auth;
    private JwtService $jwt;
    private FakeUserProvider $users;
    private FakeTokenStorage $tokenStorage;

    protected function setUp(): void
    {
        parent::setUp();

        $this->jwt = new JwtService(
            secret: 'test-secret-key-at-least-32-characters-long',
            accessTtl: 1800,
            refreshTtl: 604800,
        );

        $this->users = new FakeUserProvider();
        $this->tokenStorage = new FakeTokenStorage();

        $this->auth = new AuthService(
            users: $this->users,
            hasher: new PasswordHasher(),
            jwt: $this->jwt,
            tokenStorage: $this->tokenStorage,
        );

        $this->middleware = new AuthenticationMiddleware(
            auth: $this->auth,
            users: $this->users,
            publicPaths: ['/auth/*', '/public/*', '/health'],
            responseFactory: fn(\Throwable $e) => new FakeResponse(401),
        );
    }

    public function testPublicPathAllowsWithoutToken(): void
    {
        $request = FakeRequest::create('GET', '/auth/login');
        $handler = $this->createMockHandler(200);

        $response = $this->middleware->process($request, $handler);

        $this->assertEquals(200, $response->getStatusCode());
    }

    public function testPublicPathWithWildcard(): void
    {
        $request = FakeRequest::create('GET', '/public/some/deep/path');
        $handler = $this->createMockHandler(200);

        $response = $this->middleware->process($request, $handler);

        $this->assertEquals(200, $response->getStatusCode());
    }

    public function testExactPublicPath(): void
    {
        $request = FakeRequest::create('GET', '/health');
        $handler = $this->createMockHandler(200);

        $response = $this->middleware->process($request, $handler);

        $this->assertEquals(200, $response->getStatusCode());
    }

    public function testProtectedPathWithoutToken(): void
    {
        $request = FakeRequest::create('GET', '/api/users');
        $handler = $this->createMockHandler(200);

        $response = $this->middleware->process($request, $handler);

        $this->assertEquals(401, $response->getStatusCode());
    }

    public function testProtectedPathWithValidToken(): void
    {
        $user = new FakeUser(id: 1, email: 'test@example.com');
        $this->users->addUser($user);

        $tokens = $this->auth->issueTokenPair($user);

        $request = FakeRequest::create('GET', '/api/users', $tokens->accessToken);

        $capturedRequest = null;
        $handler = $this->createMockHandler(200, function ($req) use (&$capturedRequest) {
            $capturedRequest = $req;
        });

        $response = $this->middleware->process($request, $handler);

        $this->assertEquals(200, $response->getStatusCode());
        $this->assertNotNull($capturedRequest);
        $this->assertEquals(1, $capturedRequest->getAttribute('user_id'));
        $this->assertNotNull($capturedRequest->getAttribute('user'));
    }

    public function testProtectedPathWithInvalidToken(): void
    {
        $request = FakeRequest::create('GET', '/api/users', 'invalid.token.here');
        $handler = $this->createMockHandler(200);

        $response = $this->middleware->process($request, $handler);

        $this->assertEquals(401, $response->getStatusCode());
    }

    public function testProtectedPathWithExpiredToken(): void
    {
        // Create JWT with immediate expiration
        $expiredJwt = new JwtService(
            secret: 'test-secret-key-at-least-32-characters-long',
            accessTtl: -1,
        );

        $token = $expiredJwt->issueAccessToken(['sub' => 1]);

        $request = FakeRequest::create('GET', '/api/users', $token);
        $handler = $this->createMockHandler(200);

        $response = $this->middleware->process($request, $handler);

        $this->assertEquals(401, $response->getStatusCode());
    }

    public function testProtectedPathWithBlacklistedToken(): void
    {
        $user = new FakeUser(id: 1, email: 'test@example.com');
        $this->users->addUser($user);

        $tokens = $this->auth->issueTokenPair($user);

        // Blacklist the token
        $tokenId = $this->jwt->getTokenId($tokens->accessToken);
        if ($tokenId) {
            $this->tokenStorage->blacklist($tokenId, 3600);
        }

        $request = FakeRequest::create('GET', '/api/users', $tokens->accessToken);
        $handler = $this->createMockHandler(200);

        $response = $this->middleware->process($request, $handler);

        $this->assertEquals(401, $response->getStatusCode());
    }

    public function testTokenFromQueryParameter(): void
    {
        $user = new FakeUser(id: 1, email: 'test@example.com');
        $this->users->addUser($user);

        $tokens = $this->auth->issueTokenPair($user);

        $request = FakeRequest::create('GET', '/api/users')
            ->withQueryParams(['token' => $tokens->accessToken]);

        $handler = $this->createMockHandler(200);

        $response = $this->middleware->process($request, $handler);

        $this->assertEquals(200, $response->getStatusCode());
    }

    public function testTokenFromCookie(): void
    {
        $user = new FakeUser(id: 1, email: 'test@example.com');
        $this->users->addUser($user);

        $tokens = $this->auth->issueTokenPair($user);

        $request = FakeRequest::create('GET', '/api/users')
            ->withCookieParams(['auth_token' => $tokens->accessToken]);

        $handler = $this->createMockHandler(200);

        $response = $this->middleware->process($request, $handler);

        $this->assertEquals(200, $response->getStatusCode());
    }

    public function testPublicPathStillAttachesUserIfTokenProvided(): void
    {
        $user = new FakeUser(id: 1, email: 'test@example.com');
        $this->users->addUser($user);

        $tokens = $this->auth->issueTokenPair($user);

        $request = FakeRequest::create('GET', '/public/page', $tokens->accessToken);

        $capturedRequest = null;
        $handler = $this->createMockHandler(200, function ($req) use (&$capturedRequest) {
            $capturedRequest = $req;
        });

        $response = $this->middleware->process($request, $handler);

        $this->assertEquals(200, $response->getStatusCode());
        // User should be attached even on public path
        $this->assertEquals(1, $capturedRequest->getAttribute('user_id'));
    }

    private function createMockHandler(int $statusCode, ?callable $callback = null): RequestHandlerInterface
    {
        return new class($statusCode, $callback) implements RequestHandlerInterface {
            private $callback;

            public function __construct(
                private int $statusCode,
                ?callable $callback,
            ) {
                $this->callback = $callback;
            }

            public function handle(ServerRequestInterface $request): ResponseInterface
            {
                if ($this->callback) {
                    ($this->callback)($request);
                }

                return new class($this->statusCode) implements ResponseInterface {
                    public function __construct(private int $status) {}
                    public function getStatusCode(): int
                    {
                        return $this->status;
                    }
                    public function withStatus(int $code, string $reasonPhrase = ''): static
                    {
                        return $this;
                    }
                    public function getReasonPhrase(): string
                    {
                        return '';
                    }
                    public function getProtocolVersion(): string
                    {
                        return '1.1';
                    }
                    public function withProtocolVersion(string $version): static
                    {
                        return $this;
                    }
                    public function getHeaders(): array
                    {
                        return [];
                    }
                    public function hasHeader(string $name): bool
                    {
                        return false;
                    }
                    public function getHeader(string $name): array
                    {
                        return [];
                    }
                    public function getHeaderLine(string $name): string
                    {
                        return '';
                    }
                    public function withHeader(string $name, $value): static
                    {
                        return $this;
                    }
                    public function withAddedHeader(string $name, $value): static
                    {
                        return $this;
                    }
                    public function withoutHeader(string $name): static
                    {
                        return $this;
                    }
                    public function getBody(): \Psr\Http\Message\StreamInterface
                    {
                        throw new \RuntimeException('Not implemented');
                    }
                    public function withBody(\Psr\Http\Message\StreamInterface $body): static
                    {
                        return $this;
                    }
                };
            }
        };
    }
}
