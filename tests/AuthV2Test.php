<?php

declare(strict_types=1);

namespace MonkeysLegion\Auth\Tests;

use MonkeysLegion\Auth\Attribute\Authenticated;
use MonkeysLegion\Auth\Attribute\Authorize;
use MonkeysLegion\Auth\Attribute\Guard as GuardAttribute;
use MonkeysLegion\Auth\Attribute\RateLimit as RateLimitAttr;
use MonkeysLegion\Auth\Attribute\RequiresPermission;
use MonkeysLegion\Auth\Attribute\RequiresRole;
use MonkeysLegion\Auth\DTO\AuthResult;
use MonkeysLegion\Auth\DTO\OAuthUser;
use MonkeysLegion\Auth\DTO\PasswordPolicy;
use MonkeysLegion\Auth\DTO\TokenPair;
use MonkeysLegion\Auth\Exception\AccountLockedException;
use MonkeysLegion\Auth\Exception\AuthException;
use MonkeysLegion\Auth\Exception\ForbiddenException;
use MonkeysLegion\Auth\Exception\InvalidApiKeyException;
use MonkeysLegion\Auth\Exception\InvalidCredentialsException;
use MonkeysLegion\Auth\Exception\RateLimitExceededException;
use MonkeysLegion\Auth\Exception\TokenExpiredException;
use MonkeysLegion\Auth\Exception\TokenInvalidException;
use MonkeysLegion\Auth\Exception\TokenRevokedException;
use MonkeysLegion\Auth\Exception\TwoFactorInvalidException;
use MonkeysLegion\Auth\Exception\TwoFactorRequiredException;
use MonkeysLegion\Auth\Exception\UnauthorizedException;
use MonkeysLegion\Auth\Exception\UserAlreadyExistsException;
use MonkeysLegion\Auth\Guard\ApiKeyGuard;
use MonkeysLegion\Auth\Guard\AuthManager;
use MonkeysLegion\Auth\Guard\CompositeGuard;
use MonkeysLegion\Auth\Guard\JwtGuard;
use MonkeysLegion\Auth\Guard\SessionGuard;
use MonkeysLegion\Auth\Policy\Gate;
use MonkeysLegion\Auth\RBAC\InMemoryRoleRepository;
use MonkeysLegion\Auth\RBAC\RbacService;
use MonkeysLegion\Auth\RateLimit\InMemoryRateLimiter;
use MonkeysLegion\Auth\Service\AuthService;
use MonkeysLegion\Auth\Service\JwtService;
use MonkeysLegion\Auth\Service\PasswordHasher;
use MonkeysLegion\Auth\Storage\InMemorySession;
use MonkeysLegion\Auth\Storage\InMemoryTokenStorage;
use MonkeysLegion\Auth\Storage\InMemoryUserProvider;
use MonkeysLegion\Auth\Tests\Fixtures\FakeUser;
use MonkeysLegion\Auth\Tests\Fixtures\FakeUser2FA;
use MonkeysLegion\Auth\TwoFactor\TotpProvider;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Message\StreamInterface;
use Psr\Http\Message\UriInterface;

// ── Minimal PSR-7 Fakes ──────────────────────────────────────

class FakeUri implements UriInterface
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

class FakeStream implements StreamInterface
{
    public function __toString(): string { return ''; }
    public function close(): void {}
    public function detach() { return null; }
    public function getSize(): ?int { return 0; }
    public function tell(): int { return 0; }
    public function eof(): bool { return true; }
    public function isSeekable(): bool { return false; }
    public function seek(int $offset, int $whence = SEEK_SET): void {}
    public function rewind(): void {}
    public function isWritable(): bool { return false; }
    public function write(string $string): int { return 0; }
    public function isReadable(): bool { return false; }
    public function read(int $length): string { return ''; }
    public function getContents(): string { return ''; }
    public function getMetadata(?string $key = null): mixed { return null; }
}

class FakeRequest implements ServerRequestInterface
{
    /** @var array<string, list<string>> */
    private array $headers = [];
    /** @var array<string, mixed> */
    private array $attributes = [];
    /** @var array<string, mixed> */
    private array $queryParams = [];
    /** @var array<string, mixed> */
    private array $serverParams = [];
    /** @var array<string, string> */
    private array $cookieParams = [];

    public function __construct(
        private string $method = 'GET',
        private UriInterface $uri = new FakeUri(),
    ) {}

    public static function withBearer(string $token): self
    {
        $r = new self();
        $r->headers['Authorization'] = ["Bearer {$token}"];
        return $r;
    }

    public static function withApiKey(string $key, string $header = 'X-API-Key'): self
    {
        $r = new self();
        $r->headers[$header] = [$key];
        return $r;
    }

    // PSR-7 implementation
    public function getProtocolVersion(): string { return '1.1'; }
    public function withProtocolVersion(string $version): static { return $this; }
    public function getHeaders(): array { return $this->headers; }
    public function hasHeader(string $name): bool { return isset($this->headers[$name]); }
    public function getHeader(string $name): array { return $this->headers[$name] ?? []; }
    public function getHeaderLine(string $name): string {
        return implode(', ', $this->headers[$name] ?? []);
    }
    public function withHeader(string $name, $value): static {
        $c = clone $this; $c->headers[$name] = is_array($value) ? $value : [$value]; return $c;
    }
    public function withAddedHeader(string $name, $value): static { return $this->withHeader($name, $value); }
    public function withoutHeader(string $name): static { $c = clone $this; unset($c->headers[$name]); return $c; }
    public function getBody(): StreamInterface { return new FakeStream(); }
    public function withBody(StreamInterface $body): static { return $this; }
    public function getRequestTarget(): string { return $this->uri->getPath(); }
    public function withRequestTarget(string $requestTarget): static { return $this; }
    public function getMethod(): string { return $this->method; }
    public function withMethod(string $method): static { $c = clone $this; $c->method = $method; return $c; }
    public function getUri(): UriInterface { return $this->uri; }
    public function withUri(UriInterface $uri, bool $preserveHost = false): static { $c = clone $this; $c->uri = $uri; return $c; }
    public function getServerParams(): array { return $this->serverParams; }
    public function getCookieParams(): array { return $this->cookieParams; }
    public function withCookieParams(array $cookies): static { $c = clone $this; $c->cookieParams = $cookies; return $c; }
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

// ═══════════════════════════════════════════════════════════════
// ██ TEST SUITE ████████████████████████████████████████████████
// ═══════════════════════════════════════════════════════════════

final class AuthV2Test extends TestCase
{
    private string $jwtSecret = 'test-secret-key-at-least-32-chars!!';

    // ── Attributes ──────────────────────────────────────────

    public function test_guard_attribute(): void
    {
        $attr = new GuardAttribute('api');
        $this->assertSame('api', $attr->name);
    }

    public function test_guard_attribute_defaults(): void
    {
        $attr = new GuardAttribute();
        $this->assertSame('jwt', $attr->name);
    }

    public function test_authenticated_attribute(): void
    {
        $attr = new Authenticated(guard: 'session');
        $this->assertSame('session', $attr->guard);
    }

    public function test_authenticated_attribute_defaults(): void
    {
        $attr = new Authenticated();
        $this->assertNull($attr->guard);
    }

    public function test_authorize_attribute(): void
    {
        $attr = new Authorize(ability: 'update', model: 'App\\Post');
        $this->assertSame('update', $attr->ability);
        $this->assertSame('App\\Post', $attr->model);
    }

    public function test_requires_role_single(): void
    {
        $attr = new RequiresRole('admin');
        $this->assertSame(['admin'], $attr->roles);
        $this->assertSame('any', $attr->mode);
    }

    public function test_requires_role_multiple(): void
    {
        $attr = new RequiresRole(['admin', 'editor'], mode: 'all');
        $this->assertSame(['admin', 'editor'], $attr->roles);
        $this->assertSame('all', $attr->mode);
    }

    public function test_requires_permission_single(): void
    {
        $attr = new RequiresPermission('posts.create');
        $this->assertSame(['posts.create'], $attr->permissions);
        $this->assertSame('all', $attr->mode);
    }

    public function test_requires_permission_multiple(): void
    {
        $attr = new RequiresPermission(['posts.create', 'posts.edit'], mode: 'any');
        $this->assertSame(['posts.create', 'posts.edit'], $attr->permissions);
        $this->assertSame('any', $attr->mode);
    }

    public function test_rate_limit_attribute(): void
    {
        $attr = new RateLimitAttr(maxAttempts: 100, decaySeconds: 120, key: 'custom');
        $this->assertSame(100, $attr->maxAttempts);
        $this->assertSame(120, $attr->decaySeconds);
        $this->assertSame('custom', $attr->key);
    }

    // ── Exceptions ──────────────────────────────────────────

    public function test_exception_hierarchy(): void
    {
        $this->assertInstanceOf(\RuntimeException::class, new AuthException());
        $this->assertInstanceOf(AuthException::class, new InvalidCredentialsException());
        $this->assertInstanceOf(AuthException::class, new TokenExpiredException());
        $this->assertInstanceOf(AuthException::class, new TokenInvalidException());
        $this->assertInstanceOf(AuthException::class, new TokenRevokedException());
        $this->assertInstanceOf(AuthException::class, new UnauthorizedException());
        $this->assertInstanceOf(AuthException::class, new ForbiddenException());
        $this->assertInstanceOf(AuthException::class, new AccountLockedException());
        $this->assertInstanceOf(AuthException::class, new RateLimitExceededException());
        $this->assertInstanceOf(AuthException::class, new UserAlreadyExistsException());
        $this->assertInstanceOf(AuthException::class, new TwoFactorRequiredException());
        $this->assertInstanceOf(AuthException::class, new TwoFactorInvalidException());
        $this->assertInstanceOf(AuthException::class, new InvalidApiKeyException());
    }

    public function test_exception_status_codes(): void
    {
        $this->assertSame(401, (new AuthException())->getStatusCode());
        $this->assertSame(403, (new UnauthorizedException())->getStatusCode());
        $this->assertSame(403, (new ForbiddenException())->getStatusCode());
        $this->assertSame(423, (new AccountLockedException())->getStatusCode());
        $this->assertSame(429, (new RateLimitExceededException())->getStatusCode());
        $this->assertSame(409, (new UserAlreadyExistsException())->getStatusCode());
    }

    public function test_exception_context(): void
    {
        $e = new AuthException('test', ['key' => 'value']);
        $this->assertSame(['key' => 'value'], $e->context);
    }

    public function test_unauthorized_exception_data(): void
    {
        $e = new UnauthorizedException('update', 'App\\Post');
        $this->assertSame('update', $e->ability);
        $this->assertSame('App\\Post', $e->modelClass);
    }

    public function test_rate_limit_exception_retry(): void
    {
        $e = new RateLimitExceededException('Too many', 60);
        $this->assertSame(60, $e->retryAfter);
    }

    public function test_account_locked_exception_data(): void
    {
        $now = time() + 900;
        $e   = new AccountLockedException('Locked', $now);
        $this->assertSame($now, $e->lockedUntil);
    }

    // ── DTOs ────────────────────────────────────────────────

    public function test_token_pair(): void
    {
        $pair = new TokenPair('access', 'refresh', time() + 1800, time() + 604800, 'family-1');
        $this->assertSame('access', $pair->accessToken);
        $this->assertSame('refresh', $pair->refreshToken);
        $this->assertSame('family-1', $pair->familyId);
        $this->assertFalse($pair->isAccessExpired());
        $this->assertGreaterThan(0, $pair->accessExpiresIn());
    }

    public function test_token_pair_expired(): void
    {
        $pair = new TokenPair('a', 'r', time() - 100, time() + 1000);
        $this->assertTrue($pair->isAccessExpired());
        $this->assertSame(0, $pair->accessExpiresIn());
    }

    public function test_token_pair_to_array(): void
    {
        $pair = new TokenPair('a', 'r', time() + 100, time() + 1000);
        $arr  = $pair->toArray();
        $this->assertSame('a', $arr['access_token']);
        $this->assertSame('r', $arr['refresh_token']);
        $this->assertSame('Bearer', $arr['token_type']);
        $this->assertArrayHasKey('expires_in', $arr);
    }

    public function test_auth_result_success(): void
    {
        $user    = new FakeUser(1, 'a@b.com', 'hash');
        $tokens  = new TokenPair('a', 'r', time() + 100, time() + 1000);
        $result  = AuthResult::success($user, $tokens, 'jwt');

        $this->assertTrue($result->success);
        $this->assertSame($user, $result->user);
        $this->assertSame('jwt', $result->guard);
        $this->assertFalse($result->requires2FA);
    }

    public function test_auth_result_requires_2fa(): void
    {
        $result = AuthResult::requires2FA('challenge-token');
        $this->assertFalse($result->success);
        $this->assertTrue($result->requires2FA);
        $this->assertSame('challenge-token', $result->challengeToken);
    }

    public function test_auth_result_failure(): void
    {
        $result = AuthResult::failure('Bad request');
        $this->assertFalse($result->success);
        $this->assertSame('Bad request', $result->error);
    }

    public function test_auth_result_to_array(): void
    {
        $result = AuthResult::failure('Error');
        $arr    = $result->toArray();
        $this->assertFalse($arr['success']);
        $this->assertSame('Error', $arr['error']);
    }

    public function test_oauth_user(): void
    {
        $user = new OAuthUser('123', 'google', 'a@b.com', 'John', 'avatar.jpg');
        $this->assertSame('123', $user->providerId);
        $this->assertSame('google', $user->provider);
        $this->assertSame('a@b.com', $user->email);
        $arr = $user->toArray();
        $this->assertSame('google', $arr['provider']);
    }

    public function test_password_policy_valid(): void
    {
        $policy = new PasswordPolicy(minLength: 8);
        $errors = $policy->validate('strongPassword123');
        $this->assertSame([], $errors);
    }

    public function test_password_policy_too_short(): void
    {
        $policy = new PasswordPolicy(minLength: 10);
        $errors = $policy->validate('short');
        $this->assertNotEmpty($errors);
        $this->assertStringContainsString('at least 10', $errors[0]);
    }

    public function test_password_policy_requires_uppercase(): void
    {
        $policy = new PasswordPolicy(requireUppercase: true);
        $errors = $policy->validate('alllowercase123');
        $this->assertNotEmpty($errors);
    }

    public function test_password_policy_requires_numbers(): void
    {
        $policy = new PasswordPolicy(requireNumbers: true);
        $errors = $policy->validate('NoNumbersHere');
        $this->assertNotEmpty($errors);
    }

    public function test_password_policy_requires_symbols(): void
    {
        $policy = new PasswordPolicy(requireSymbols: true);
        $errors = $policy->validate('NoSymbols123');
        $this->assertNotEmpty($errors);
    }

    public function test_password_policy_rejects_common(): void
    {
        $policy = new PasswordPolicy(rejectCommon: true);
        $errors = $policy->validate('password');
        $this->assertNotEmpty($errors);
        $this->assertStringContainsString('too common', $errors[0]);
    }

    public function test_password_policy_max_length(): void
    {
        $policy = new PasswordPolicy(maxLength: 10);
        $errors = $policy->validate('thisIsWayTooLongForThePolicy');
        $this->assertNotEmpty($errors);
    }

    // ── Password Hasher ─────────────────────────────────────

    public function test_hasher_hash_and_verify(): void
    {
        $hasher = new PasswordHasher(policy: new PasswordPolicy(rejectCommon: false));
        $hash   = $hasher->hash('ValidPass123');
        $this->assertTrue($hasher->verify('ValidPass123', $hash));
        $this->assertFalse($hasher->verify('WrongPass', $hash));
    }

    public function test_hasher_rejects_policy_violation(): void
    {
        $hasher = new PasswordHasher(policy: new PasswordPolicy(minLength: 20));
        $this->expectException(\InvalidArgumentException::class);
        $hasher->hash('short');
    }

    public function test_hasher_needs_rehash(): void
    {
        $hasher = new PasswordHasher(bcryptCost: 12, policy: new PasswordPolicy(rejectCommon: false));
        // A hash with cost 4 should need rehashing at cost 12
        $weakHash = password_hash('test', PASSWORD_BCRYPT, ['cost' => 4]);
        $this->assertTrue($hasher->needsRehash($weakHash));
    }

    public function test_hasher_validate_policy(): void
    {
        $hasher = new PasswordHasher(policy: new PasswordPolicy(requireUppercase: true));
        $errors = $hasher->validatePolicy('alllower');
        $this->assertNotEmpty($errors);
    }

    public function test_hasher_special_characters(): void
    {
        $hasher = new PasswordHasher(policy: new PasswordPolicy(rejectCommon: false));
        $pass   = 'P@$$w0rd!#%^&*()';
        $hash   = $hasher->hash($pass);
        $this->assertTrue($hasher->verify($pass, $hash));
    }

    public function test_hasher_unicode(): void
    {
        $hasher = new PasswordHasher(policy: new PasswordPolicy(rejectCommon: false));
        $pass   = 'пароль密码パスワード!1';
        $hash   = $hasher->hash($pass);
        $this->assertTrue($hasher->verify($pass, $hash));
    }

    // ── JWT Service ─────────────────────────────────────────

    public function test_jwt_issue_and_decode(): void
    {
        $jwt    = new JwtService($this->jwtSecret);
        $token  = $jwt->issueAccessToken(['sub' => 42, 'ver' => 1]);
        $claims = $jwt->decode($token);

        $this->assertSame(42, $claims['sub']);
        $this->assertSame(1, $claims['ver']);
        $this->assertArrayHasKey('jti', $claims);
        $this->assertArrayHasKey('iat', $claims);
        $this->assertArrayHasKey('exp', $claims);
    }

    public function test_jwt_access_ttl_property(): void
    {
        $jwt = new JwtService($this->jwtSecret, accessTtl: 600);
        $this->assertSame(600, $jwt->accessTtl);
    }

    public function test_jwt_refresh_ttl_property(): void
    {
        $jwt = new JwtService($this->jwtSecret, refreshTtl: 86400);
        $this->assertSame(86400, $jwt->refreshTtl);
    }

    public function test_jwt_refresh_token_has_family(): void
    {
        $jwt    = new JwtService($this->jwtSecret);
        $token  = $jwt->issueRefreshToken(['sub' => 1, 'ver' => 0], 'family-abc');
        $claims = $jwt->decode($token);

        $this->assertSame('refresh', $claims['type']);
        $this->assertSame('family-abc', $claims['family']);
    }

    public function test_jwt_expired_token_throws(): void
    {
        $jwt   = new JwtService($this->jwtSecret, accessTtl: -10);
        $token = $jwt->issueAccessToken(['sub' => 1]);

        $this->expectException(TokenExpiredException::class);
        $jwt->decode($token);
    }

    public function test_jwt_invalid_token_throws(): void
    {
        $jwt = new JwtService($this->jwtSecret);
        $this->expectException(TokenInvalidException::class);
        $jwt->decode('invalid.token.here');
    }

    public function test_jwt_decode_with_leeway(): void
    {
        $jwt   = new JwtService($this->jwtSecret, accessTtl: -5);
        $token = $jwt->issueAccessToken(['sub' => 1]);

        // Should work with enough leeway
        $claims = $jwt->decodeWithLeeway($token, 60);
        $this->assertSame(1, $claims['sub']);
    }

    public function test_jwt_get_expiration(): void
    {
        $jwt   = new JwtService($this->jwtSecret);
        $token = $jwt->issueAccessToken(['sub' => 1]);
        $exp   = $jwt->getExpiration($token);
        $this->assertNotNull($exp);
        $this->assertGreaterThan(time(), $exp);
    }

    public function test_jwt_is_expired_false(): void
    {
        $jwt   = new JwtService($this->jwtSecret);
        $token = $jwt->issueAccessToken(['sub' => 1]);
        $this->assertFalse($jwt->isExpired($token));
    }

    public function test_jwt_get_token_id(): void
    {
        $jwt   = new JwtService($this->jwtSecret);
        $token = $jwt->issueAccessToken(['sub' => 1]);
        $jti   = $jwt->getTokenId($token);
        $this->assertNotNull($jti);
        $this->assertSame(32, strlen($jti));
    }

    public function test_jwt_generate_token_id_unique(): void
    {
        $jwt = new JwtService($this->jwtSecret);
        $ids = [];
        for ($i = 0; $i < 50; $i++) {
            $ids[] = $jwt->generateTokenId();
        }
        $this->assertCount(50, array_unique($ids));
    }

    public function test_jwt_with_issuer_and_audience(): void
    {
        $jwt    = new JwtService($this->jwtSecret, issuer: 'ml-auth', audience: 'ml-api');
        $token  = $jwt->issueAccessToken(['sub' => 1]);
        $claims = $jwt->decode($token);
        $this->assertSame('ml-auth', $claims['iss']);
        $this->assertSame('ml-api', $claims['aud']);
    }

    // ── Guard: JwtGuard ─────────────────────────────────────

    public function test_jwt_guard_authenticates(): void
    {
        $jwt   = new JwtService($this->jwtSecret);
        $users = new InMemoryUserProvider();
        $user  = new FakeUser(1, 'a@b.com', 'hash');
        $users->addUser($user);

        $guard   = new JwtGuard($jwt, $users);
        $token   = $jwt->issueAccessToken(['sub' => 1, 'ver' => 0]);
        $request = FakeRequest::withBearer($token);

        $result = $guard->authenticate($request);
        $this->assertNotNull($result);
        $this->assertSame(1, $result->getAuthIdentifier());
        $this->assertTrue($guard->check());
        $this->assertFalse($guard->guest());
        $this->assertSame(1, $guard->id());
        $this->assertSame('jwt', $guard->name());
    }

    public function test_jwt_guard_returns_null_without_token(): void
    {
        $jwt   = new JwtService($this->jwtSecret);
        $users = new InMemoryUserProvider();
        $guard = new JwtGuard($jwt, $users);

        $result = $guard->authenticate(new FakeRequest());
        $this->assertNull($result);
        $this->assertTrue($guard->guest());
    }

    public function test_jwt_guard_rejects_blacklisted_token(): void
    {
        $jwt     = new JwtService($this->jwtSecret);
        $users   = new InMemoryUserProvider();
        $storage = new InMemoryTokenStorage();
        $user    = new FakeUser(1, 'a@b.com', 'hash');
        $users->addUser($user);

        $guard = new JwtGuard($jwt, $users, $storage);
        $token = $jwt->issueAccessToken(['sub' => 1, 'ver' => 0]);
        $jti   = $jwt->getTokenId($token);
        $storage->blacklist($jti, 3600);

        $result = $guard->authenticate(FakeRequest::withBearer($token));
        $this->assertNull($result);
    }

    public function test_jwt_guard_validates_token(): void
    {
        $jwt   = new JwtService($this->jwtSecret);
        $users = new InMemoryUserProvider();
        $guard = new JwtGuard($jwt, $users);

        $token = $jwt->issueAccessToken(['sub' => 1, 'ver' => 0]);
        $this->assertTrue($guard->validate(['token' => $token]));
        $this->assertFalse($guard->validate(['token' => 'bad']));
        $this->assertFalse($guard->validate([]));
    }

    // ── Guard: ApiKeyGuard ──────────────────────────────────

    public function test_api_key_guard_authenticates(): void
    {
        $users = new InMemoryUserProvider();
        $user  = new FakeUser(1, 'a@b.com', 'hash');
        $users->addUser($user);
        $users->addApiKey(1, 'secret-key-123');

        $guard   = new ApiKeyGuard($users);
        $request = FakeRequest::withApiKey('secret-key-123');

        $result = $guard->authenticate($request);
        $this->assertNotNull($result);
        $this->assertSame(1, $result->getAuthIdentifier());
        $this->assertSame('api-key', $guard->name());
    }

    public function test_api_key_guard_rejects_invalid(): void
    {
        $users = new InMemoryUserProvider();
        $guard = new ApiKeyGuard($users);

        $result = $guard->authenticate(FakeRequest::withApiKey('invalid'));
        $this->assertNull($result);
    }

    public function test_api_key_guard_validates(): void
    {
        $users = new InMemoryUserProvider();
        $user  = new FakeUser(1, 'a@b.com', 'hash');
        $users->addUser($user);
        $users->addApiKey(1, 'key-1');

        $guard = new ApiKeyGuard($users);
        $this->assertTrue($guard->validate(['api_key' => 'key-1']));
        $this->assertFalse($guard->validate(['api_key' => 'bad']));
    }

    // ── Guard: CompositeGuard ───────────────────────────────

    public function test_composite_guard_tries_in_order(): void
    {
        $jwt   = new JwtService($this->jwtSecret);
        $users = new InMemoryUserProvider();
        $user  = new FakeUser(1, 'a@b.com', 'hash');
        $users->addUser($user);
        $users->addApiKey(1, 'my-key');

        $jwtGuard = new JwtGuard($jwt, $users);
        $apiGuard = new ApiKeyGuard($users);
        $composite = new CompositeGuard([$jwtGuard, $apiGuard]);

        // API key request — JWT fails, API key succeeds
        $request = FakeRequest::withApiKey('my-key');
        $result  = $composite->authenticate($request);

        $this->assertNotNull($result);
        $this->assertSame('api-key', $composite->name());
        $this->assertSame($apiGuard, $composite->matchedGuard());
    }

    public function test_composite_guard_returns_null_if_none_match(): void
    {
        $jwt   = new JwtService($this->jwtSecret);
        $users = new InMemoryUserProvider();

        $composite = new CompositeGuard([new JwtGuard($jwt, $users), new ApiKeyGuard($users)]);
        $result    = $composite->authenticate(new FakeRequest());

        $this->assertNull($result);
        $this->assertNull($composite->matchedGuard());
    }

    // ── Guard: AuthManager ──────────────────────────────────

    public function test_auth_manager_registers_guards(): void
    {
        $jwt   = new JwtService($this->jwtSecret);
        $users = new InMemoryUserProvider();

        $manager = new AuthManager();
        $manager->register('jwt', new JwtGuard($jwt, $users));
        $manager->register('api-key', new ApiKeyGuard($users));

        $this->assertTrue($manager->has('jwt'));
        $this->assertTrue($manager->has('api-key'));
        $this->assertFalse($manager->has('session'));
        $this->assertSame(['jwt', 'api-key'], $manager->getRegisteredGuards());
    }

    public function test_auth_manager_default_guard(): void
    {
        $jwt   = new JwtService($this->jwtSecret);
        $users = new InMemoryUserProvider();

        $manager = new AuthManager('jwt');
        $manager->register('jwt', new JwtGuard($jwt, $users));

        $this->assertSame('jwt', $manager->defaultGuard);
        $this->assertSame('jwt', $manager->guard()->name());
    }

    public function test_auth_manager_throws_for_unknown_guard(): void
    {
        $manager = new AuthManager();
        $this->expectException(\InvalidArgumentException::class);
        $manager->guard('nonexistent');
    }

    // ── Gate ────────────────────────────────────────────────

    public function test_gate_define_and_check(): void
    {
        $gate = new Gate();
        $gate->define('edit-post', fn($user) => $user !== null);

        $user = new FakeUser(1, 'a@b.com', 'hash');
        $this->assertTrue($gate->allows($user, 'edit-post'));
        $this->assertFalse($gate->allows(null, 'edit-post'));
    }

    public function test_gate_denies(): void
    {
        $gate = new Gate();
        $gate->define('admin', fn($user) => false);

        $user = new FakeUser(1, 'a@b.com', 'hash');
        $this->assertTrue($gate->denies($user, 'admin'));
    }

    public function test_gate_authorize_throws(): void
    {
        $gate = new Gate();
        $gate->define('admin', fn($user) => false);

        $user = new FakeUser(1, 'a@b.com', 'hash');

        $this->expectException(UnauthorizedException::class);
        $gate->authorize($user, 'admin');
    }

    public function test_gate_before_callback_overrides(): void
    {
        $gate = new Gate();
        $gate->define('edit', fn() => false);
        $gate->before(fn($user) => $user !== null && $user->getAuthIdentifier() === 1 ? true : null);

        $admin = new FakeUser(1, 'admin@b.com', 'hash');
        $other = new FakeUser(2, 'user@b.com', 'hash');

        $this->assertTrue($gate->allows($admin, 'edit'));
        $this->assertFalse($gate->allows($other, 'edit'));
    }

    public function test_gate_after_callback(): void
    {
        $gate = new Gate();
        $gate->define('view', fn() => false);
        $gate->after(fn($user, $ability, $result) => true); // Override to allow

        $user = new FakeUser(1, 'a@b.com', 'hash');
        $this->assertTrue($gate->allows($user, 'view'));
    }

    public function test_gate_all(): void
    {
        $gate = new Gate();
        $gate->define('read', fn() => true);
        $gate->define('write', fn() => false);

        $user = new FakeUser(1, 'a@b.com', 'hash');
        $this->assertFalse($gate->all($user, ['read', 'write']));
    }

    public function test_gate_any(): void
    {
        $gate = new Gate();
        $gate->define('read', fn() => true);
        $gate->define('write', fn() => false);

        $user = new FakeUser(1, 'a@b.com', 'hash');
        $this->assertTrue($gate->any($user, ['read', 'write']));
    }

    public function test_gate_inspect(): void
    {
        $gate = new Gate();
        $gate->define('admin', fn() => false);

        $user   = new FakeUser(1, 'a@b.com', 'hash');
        $result = $gate->inspect($user, 'admin');

        $this->assertFalse($result['allowed']);
        $this->assertStringContainsString('Denied', $result['reason']);
    }

    public function test_gate_inspect_undefined(): void
    {
        $gate   = new Gate();
        $result = $gate->inspect(null, 'nonexistent');

        $this->assertFalse($result['allowed']);
        $this->assertStringContainsString('not defined', $result['reason']);
    }

    public function test_gate_undefined_ability_denied(): void
    {
        $gate = new Gate();
        $user = new FakeUser(1, 'a@b.com', 'hash');
        $this->assertFalse($gate->allows($user, 'nonexistent'));
    }

    // ── RBAC ────────────────────────────────────────────────

    public function test_rbac_assign_and_check_role(): void
    {
        $repo = new InMemoryRoleRepository();
        $rbac = new RbacService($repo);

        $repo->createRole('admin');
        $rbac->assignRole(1, 'admin');

        $this->assertTrue($rbac->hasRole(1, 'admin'));
        $this->assertFalse($rbac->hasRole(1, 'editor'));
    }

    public function test_rbac_has_any_role(): void
    {
        $repo = new InMemoryRoleRepository();
        $rbac = new RbacService($repo);
        $rbac->assignRole(1, 'editor');

        $this->assertTrue($rbac->hasAnyRole(1, ['admin', 'editor']));
        $this->assertFalse($rbac->hasAnyRole(1, ['admin', 'moderator']));
    }

    public function test_rbac_has_all_roles(): void
    {
        $repo = new InMemoryRoleRepository();
        $rbac = new RbacService($repo);
        $rbac->assignRole(1, 'admin');
        $rbac->assignRole(1, 'editor');

        $this->assertTrue($rbac->hasAllRoles(1, ['admin', 'editor']));
        $this->assertFalse($rbac->hasAllRoles(1, ['admin', 'moderator']));
    }

    public function test_rbac_permissions_with_wildcard(): void
    {
        $repo = new InMemoryRoleRepository();
        $rbac = new RbacService($repo);
        $rbac->assignPermission(1, 'posts.*');

        $this->assertTrue($rbac->hasPermission(1, 'posts.create'));
        $this->assertTrue($rbac->hasPermission(1, 'posts.edit'));
        $this->assertFalse($rbac->hasPermission(1, 'users.edit'));
    }

    public function test_rbac_super_admin(): void
    {
        $repo = new InMemoryRoleRepository();
        $rbac = new RbacService($repo);
        $rbac->assignPermission(1, '*');

        $this->assertTrue($rbac->hasPermission(1, 'anything'));
        $this->assertTrue($rbac->hasPermission(1, 'deeply.nested.permission'));
    }

    public function test_rbac_role_permissions(): void
    {
        $repo = new InMemoryRoleRepository();
        $rbac = new RbacService($repo);

        $repo->createRole('editor');
        $repo->createPermission('posts.create');
        $repo->createPermission('posts.edit');
        $repo->assignPermissionToRole('editor', 'posts.create');
        $repo->assignPermissionToRole('editor', 'posts.edit');
        $rbac->assignRole(1, 'editor');

        $this->assertTrue($rbac->hasPermission(1, 'posts.create'));
        $this->assertTrue($rbac->hasPermission(1, 'posts.edit'));
        $this->assertFalse($rbac->hasPermission(1, 'posts.delete'));
    }

    public function test_rbac_remove_role(): void
    {
        $repo = new InMemoryRoleRepository();
        $rbac = new RbacService($repo);
        $rbac->assignRole(1, 'admin');
        $this->assertTrue($rbac->hasRole(1, 'admin'));

        $rbac->removeRole(1, 'admin');
        $this->assertFalse($rbac->hasRole(1, 'admin'));
    }

    public function test_rbac_clear_cache(): void
    {
        $repo = new InMemoryRoleRepository();
        $rbac = new RbacService($repo);
        $rbac->assignRole(1, 'admin');
        $rbac->getUserRoles(1); // Populate cache
        $rbac->clearCache(1);
        // Should still work after cache clear
        $this->assertTrue($rbac->hasRole(1, 'admin'));
    }

    public function test_rbac_with_authenticatable(): void
    {
        $repo = new InMemoryRoleRepository();
        $rbac = new RbacService($repo);
        $user = new FakeUser(1, 'a@b.com', 'hash');
        $rbac->assignRole(1, 'admin');

        $this->assertTrue($rbac->hasRole($user, 'admin'));
    }

    public function test_rbac_role_repo_operations(): void
    {
        $repo = new InMemoryRoleRepository();
        $id   = $repo->createRole('admin', 'Administrator');
        $this->assertGreaterThan(0, $id);
        $this->assertTrue($repo->roleExists('admin'));
        $this->assertFalse($repo->roleExists('unknown'));

        $roles = $repo->getAllRoles();
        $this->assertCount(1, $roles);
        $this->assertSame('admin', $roles[0]['name']);
    }

    // ── Traits ──────────────────────────────────────────────

    public function test_authenticatable_trait(): void
    {
        $user = new FakeUser(42, 'a@b.com', 'hashed');
        $this->assertSame(42, $user->getAuthIdentifier());
        $this->assertSame('id', $user->getAuthIdentifierName());
        $this->assertSame('hashed', $user->getAuthPassword());
        $this->assertSame(0, $user->getTokenVersion());
        $this->assertNull($user->getRememberToken());

        $user->setRememberToken('remember-me');
        $this->assertSame('remember-me', $user->getRememberToken());
    }

    public function test_has_roles_trait(): void
    {
        $user = new FakeUser(1, 'a@b.com', 'hash', roles: ['admin', 'editor']);
        $this->assertSame(['admin', 'editor'], $user->getRoles());
        $this->assertTrue($user->hasRole('admin'));
        $this->assertFalse($user->hasRole('viewer'));
        $this->assertTrue($user->hasAnyRole(['viewer', 'admin']));
        $this->assertTrue($user->hasAllRoles(['admin', 'editor']));
        $this->assertFalse($user->hasAllRoles(['admin', 'moderator']));
    }

    public function test_has_permissions_trait(): void
    {
        $user = new FakeUser(1, 'a@b.com', 'hash', permissions: ['posts.*', 'users.view']);
        $this->assertTrue($user->hasPermission('posts.create'));
        $this->assertTrue($user->hasPermission('posts.edit'));
        $this->assertTrue($user->hasPermission('users.view'));
        $this->assertFalse($user->hasPermission('users.edit'));
        $this->assertTrue($user->hasAnyPermission(['users.edit', 'posts.create']));
        $this->assertFalse($user->hasAllPermissions(['posts.create', 'users.edit']));
    }

    public function test_has_permissions_super_admin(): void
    {
        $user = new FakeUser(1, 'a@b.com', 'hash', permissions: ['*']);
        $this->assertTrue($user->hasPermission('anything'));
    }

    // ── TOTP 2FA ────────────────────────────────────────────

    public function test_totp_generate_secret(): void
    {
        $totp   = new TotpProvider();
        $secret = $totp->generateSecret();
        $this->assertMatchesRegularExpression('/^[A-Z2-7]+$/', $secret);
        $this->assertGreaterThanOrEqual(16, strlen($secret));
    }

    public function test_totp_secret_unique(): void
    {
        $totp    = new TotpProvider();
        $secrets = [];
        for ($i = 0; $i < 10; $i++) {
            $secrets[] = $totp->generateSecret();
        }
        $this->assertCount(10, array_unique($secrets));
    }

    public function test_totp_provisioning_uri(): void
    {
        $totp = new TotpProvider();
        $uri  = $totp->getProvisioningUri('SECRET', 'user@example.com', 'MyApp');
        $this->assertStringStartsWith('otpauth://totp/', $uri);
        $this->assertStringContainsString('secret=SECRET', $uri);
        $this->assertStringContainsString('issuer=MyApp', $uri);
    }

    public function test_totp_backup_codes(): void
    {
        $totp  = new TotpProvider();
        $codes = $totp->generateBackupCodes(8);
        $this->assertCount(8, $codes);
        $this->assertCount(8, array_unique($codes));
        foreach ($codes as $code) {
            $this->assertMatchesRegularExpression('/^[0-9A-F]{8}$/', $code);
        }
    }

    public function test_totp_verify_rejects_wrong_length(): void
    {
        $totp   = new TotpProvider();
        $secret = $totp->generateSecret();
        $this->assertFalse($totp->verify($secret, '123'));
        $this->assertFalse($totp->verify($secret, '12345678'));
    }

    public function test_totp_verify_strips_whitespace(): void
    {
        $totp   = new TotpProvider();
        $secret = $totp->generateSecret();
        // Even with whitespace, wrong code should still fail
        $this->assertFalse($totp->verify($secret, '  123  '));
    }

    // ── Rate Limiter ────────────────────────────────────────

    public function test_rate_limiter_allows_under_limit(): void
    {
        $limiter = new InMemoryRateLimiter();
        $this->assertTrue($limiter->attempt('test', 5, 60));
        $this->assertTrue($limiter->attempt('test', 5, 60));
        $this->assertSame(3, $limiter->remaining('test', 5));
    }

    public function test_rate_limiter_blocks_over_limit(): void
    {
        $limiter = new InMemoryRateLimiter();
        for ($i = 0; $i < 5; $i++) {
            $limiter->attempt('test', 5, 60);
        }
        $this->assertFalse($limiter->attempt('test', 5, 60));
        $this->assertSame(0, $limiter->remaining('test', 5));
    }

    public function test_rate_limiter_clear(): void
    {
        $limiter = new InMemoryRateLimiter();
        for ($i = 0; $i < 5; $i++) {
            $limiter->hit('test', 60);
        }
        $limiter->clear('test');
        $this->assertTrue($limiter->attempt('test', 5, 60));
    }

    public function test_rate_limiter_available_in(): void
    {
        $limiter = new InMemoryRateLimiter();
        $limiter->hit('test', 60);
        $this->assertGreaterThan(0, $limiter->availableIn('test'));
        $this->assertSame(0, $limiter->availableIn('nonexistent'));
    }

    // ── Token Storage ───────────────────────────────────────

    public function test_token_storage_store_and_get(): void
    {
        $storage = new InMemoryTokenStorage();
        $storage->store('tok-1', ['user_id' => 1], 3600);

        $data = $storage->get('tok-1');
        $this->assertSame(1, $data['user_id']);
    }

    public function test_token_storage_returns_null_for_missing(): void
    {
        $storage = new InMemoryTokenStorage();
        $this->assertNull($storage->get('nonexistent'));
    }

    public function test_token_storage_blacklist(): void
    {
        $storage = new InMemoryTokenStorage();
        $this->assertFalse($storage->isBlacklisted('tok-1'));

        $storage->blacklist('tok-1', 3600);
        $this->assertTrue($storage->isBlacklisted('tok-1'));
    }

    public function test_token_storage_remove_all_for_user(): void
    {
        $storage = new InMemoryTokenStorage();
        $storage->store('tok-1', ['user_id' => 1], 3600);
        $storage->store('tok-2', ['user_id' => 1], 3600);
        $storage->store('tok-3', ['user_id' => 2], 3600);

        $storage->removeAllForUser(1);

        $this->assertNull($storage->get('tok-1'));
        $this->assertNull($storage->get('tok-2'));
        $this->assertNotNull($storage->get('tok-3'));
    }

    // ── AuthService (Integration) ───────────────────────────

    public function test_auth_service_login_success(): void
    {
        $hasher  = new PasswordHasher(policy: new PasswordPolicy(rejectCommon: false));
        $jwt     = new JwtService($this->jwtSecret);
        $users   = new InMemoryUserProvider();
        $storage = new InMemoryTokenStorage();
        $limiter = new InMemoryRateLimiter();

        $hash = $hasher->hash('ValidPassword1');
        $user = new FakeUser(1, 'a@b.com', $hash);
        $users->addUser($user);

        $auth   = new AuthService($users, $hasher, $jwt, $storage, $limiter);
        $result = $auth->login('a@b.com', 'ValidPassword1');

        $this->assertTrue($result->success);
        $this->assertNotNull($result->tokens);
        $this->assertSame('jwt', $result->guard);
    }

    public function test_auth_service_login_invalid_password(): void
    {
        $hasher = new PasswordHasher(policy: new PasswordPolicy(rejectCommon: false));
        $jwt    = new JwtService($this->jwtSecret);
        $users  = new InMemoryUserProvider();

        $hash = $hasher->hash('CorrectPassword1');
        $user = new FakeUser(1, 'a@b.com', $hash);
        $users->addUser($user);

        $auth = new AuthService($users, $hasher, $jwt);

        $this->expectException(InvalidCredentialsException::class);
        $auth->login('a@b.com', 'WrongPassword');
    }

    public function test_auth_service_login_unknown_email(): void
    {
        $hasher = new PasswordHasher(policy: new PasswordPolicy(rejectCommon: false));
        $jwt    = new JwtService($this->jwtSecret);
        $users  = new InMemoryUserProvider();

        $auth = new AuthService($users, $hasher, $jwt);

        $this->expectException(InvalidCredentialsException::class);
        $auth->login('unknown@b.com', 'password');
    }

    public function test_auth_service_token_validation(): void
    {
        $hasher = new PasswordHasher(policy: new PasswordPolicy(rejectCommon: false));
        $jwt    = new JwtService($this->jwtSecret);
        $users  = new InMemoryUserProvider();

        $hash = $hasher->hash('ValidPassword1');
        $user = new FakeUser(1, 'a@b.com', $hash);
        $users->addUser($user);

        $auth   = new AuthService($users, $hasher, $jwt);
        $result = $auth->login('a@b.com', 'ValidPassword1');

        $claims = $auth->validateAccessToken($result->tokens->accessToken);
        $this->assertSame(1, $claims['sub']);
    }

    public function test_auth_service_get_user_from_token(): void
    {
        $hasher = new PasswordHasher(policy: new PasswordPolicy(rejectCommon: false));
        $jwt    = new JwtService($this->jwtSecret);
        $users  = new InMemoryUserProvider();

        $hash = $hasher->hash('ValidPassword1');
        $user = new FakeUser(1, 'a@b.com', $hash);
        $users->addUser($user);

        $auth   = new AuthService($users, $hasher, $jwt);
        $result = $auth->login('a@b.com', 'ValidPassword1');

        $found = $auth->getUserFromToken($result->tokens->accessToken);
        $this->assertNotNull($found);
        $this->assertSame(1, $found->getAuthIdentifier());
    }

    public function test_auth_service_get_user_from_invalid_token(): void
    {
        $hasher = new PasswordHasher(policy: new PasswordPolicy(rejectCommon: false));
        $jwt    = new JwtService($this->jwtSecret);
        $users  = new InMemoryUserProvider();

        $auth = new AuthService($users, $hasher, $jwt);
        $this->assertNull($auth->getUserFromToken('invalid'));
    }

    public function test_auth_service_logout(): void
    {
        $hasher  = new PasswordHasher(policy: new PasswordPolicy(rejectCommon: false));
        $jwt     = new JwtService($this->jwtSecret);
        $users   = new InMemoryUserProvider();
        $storage = new InMemoryTokenStorage();

        $hash = $hasher->hash('ValidPassword1');
        $user = new FakeUser(1, 'a@b.com', $hash);
        $users->addUser($user);

        $auth   = new AuthService($users, $hasher, $jwt, $storage);
        $result = $auth->login('a@b.com', 'ValidPassword1');

        $auth->logout($result->tokens->accessToken);

        // Token should now be blacklisted
        $jti = $jwt->getTokenId($result->tokens->accessToken);
        $this->assertTrue($storage->isBlacklisted($jti));
    }

    public function test_auth_service_refresh_token(): void
    {
        $hasher  = new PasswordHasher(policy: new PasswordPolicy(rejectCommon: false));
        $jwt     = new JwtService($this->jwtSecret);
        $users   = new InMemoryUserProvider();
        $storage = new InMemoryTokenStorage();

        $hash = $hasher->hash('ValidPassword1');
        $user = new FakeUser(1, 'a@b.com', $hash);
        $users->addUser($user);

        $auth   = new AuthService($users, $hasher, $jwt, $storage);
        $result = $auth->login('a@b.com', 'ValidPassword1');

        $newTokens = $auth->refresh($result->tokens->refreshToken);
        $this->assertNotSame($result->tokens->accessToken, $newTokens->accessToken);
    }

    public function test_auth_service_issue_token_pair(): void
    {
        $hasher = new PasswordHasher(policy: new PasswordPolicy(rejectCommon: false));
        $jwt    = new JwtService($this->jwtSecret);
        $users  = new InMemoryUserProvider();

        $user = new FakeUser(1, 'a@b.com', 'hash');
        $auth = new AuthService($users, $hasher, $jwt);

        $pair = $auth->issueTokenPair($user);
        $this->assertNotEmpty($pair->accessToken);
        $this->assertNotEmpty($pair->refreshToken);
        $this->assertGreaterThan(time(), $pair->accessExpiresAt);
    }

    // ── User Provider ───────────────────────────────────────

    public function test_in_memory_user_provider(): void
    {
        $provider = new InMemoryUserProvider();
        $user     = new FakeUser(1, 'a@b.com', 'hash');
        $provider->addUser($user);

        $this->assertSame($user, $provider->findById(1));
        $this->assertSame($user, $provider->findByEmail('a@b.com'));
        $this->assertNull($provider->findById(999));
        $this->assertNull($provider->findByEmail('unknown@b.com'));
    }

    public function test_in_memory_user_provider_api_key(): void
    {
        $provider = new InMemoryUserProvider();
        $user     = new FakeUser(1, 'a@b.com', 'hash');
        $provider->addUser($user);
        $provider->addApiKey(1, 'key-123');

        $this->assertSame($user, $provider->findByApiKey('key-123'));
        $this->assertNull($provider->findByApiKey('wrong'));
    }

    public function test_in_memory_user_provider_remember_token(): void
    {
        $provider = new InMemoryUserProvider();
        $user     = new FakeUser(1, 'a@b.com', 'hash');
        $provider->addUser($user);

        $user->setRememberToken('rem-token');
        $this->assertSame($user, $provider->findByRememberToken(1, 'rem-token'));
        $this->assertNull($provider->findByRememberToken(1, 'wrong'));
    }

    // ── Guard: SessionGuard ─────────────────────────────────

    public function test_session_guard_login_and_authenticate(): void
    {
        $session  = new InMemorySession();
        $users    = new InMemoryUserProvider();
        $user     = new FakeUser(1, 'a@b.com', 'hash');
        $users->addUser($user);

        $guard = new SessionGuard($session, $users);
        $this->assertSame('session', $guard->name());
        $this->assertTrue($guard->guest());

        // Login
        $guard->login($user);
        $this->assertTrue($guard->check());
        $this->assertFalse($guard->guest());
        $this->assertSame(1, $guard->id());
        $this->assertSame($user, $guard->user());
    }

    public function test_session_guard_authenticate_from_session(): void
    {
        $session = new InMemorySession();
        $users   = new InMemoryUserProvider();
        $user    = new FakeUser(1, 'a@b.com', 'hash');
        $users->addUser($user);

        // Simulate previous login by putting data in session
        $session->put('_ml_auth_id', 1);
        $session->put('_ml_auth_ver', 0);

        $guard  = new SessionGuard($session, $users);
        $result = $guard->authenticate(new FakeRequest());

        $this->assertNotNull($result);
        $this->assertSame(1, $result->getAuthIdentifier());
    }

    public function test_session_guard_rejects_stale_version(): void
    {
        $session = new InMemorySession();
        $users   = new InMemoryUserProvider();
        $user    = new FakeUser(1, 'a@b.com', 'hash', tokenVersion: 5);
        $users->addUser($user);

        // Session has old version
        $session->put('_ml_auth_id', 1);
        $session->put('_ml_auth_ver', 3);

        $guard  = new SessionGuard($session, $users);
        $result = $guard->authenticate(new FakeRequest());

        $this->assertNull($result);
    }

    public function test_session_guard_logout(): void
    {
        $session = new InMemorySession();
        $users   = new InMemoryUserProvider();
        $user    = new FakeUser(1, 'a@b.com', 'hash');
        $users->addUser($user);

        $guard = new SessionGuard($session, $users);
        $guard->login($user);
        $this->assertTrue($guard->check());

        $guard->logout();
        $this->assertTrue($guard->guest());
        $this->assertNull($guard->user());
        $this->assertNull($guard->id());
    }

    public function test_session_guard_validates_credentials(): void
    {
        $session = new InMemorySession();
        $users   = new InMemoryUserProvider();
        $hash    = password_hash('secret', PASSWORD_BCRYPT);
        $user    = new FakeUser(1, 'a@b.com', $hash);
        $users->addUser($user);

        $guard = new SessionGuard($session, $users);
        $this->assertTrue($guard->validate(['email' => 'a@b.com', 'password' => 'secret']));
        $this->assertFalse($guard->validate(['email' => 'a@b.com', 'password' => 'wrong']));
        $this->assertFalse($guard->validate(['email' => 'missing@b.com', 'password' => 'secret']));
    }

    public function test_session_guard_regenerates_session_on_login(): void
    {
        $session = new InMemorySession();
        $users   = new InMemoryUserProvider();
        $user    = new FakeUser(1, 'a@b.com', 'hash');
        $users->addUser($user);

        $oldId = $session->getId();
        $guard = new SessionGuard($session, $users);
        $guard->login($user);
        $newId = $session->getId();

        $this->assertNotSame($oldId, $newId);
    }

    public function test_session_guard_via_remember(): void
    {
        $session = new InMemorySession();
        $users   = new InMemoryUserProvider();
        $guard   = new SessionGuard($session, $users);
        $this->assertFalse($guard->viaRemember());
    }

    public function test_session_guard_property_hook(): void
    {
        $session = new InMemorySession();
        $users   = new InMemoryUserProvider();
        $user    = new FakeUser(1, 'a@b.com', 'hash');
        $users->addUser($user);

        $guard = new SessionGuard($session, $users);
        $this->assertNull($guard->currentUser);

        $guard->login($user);
        $this->assertSame($user, $guard->currentUser);
    }

    // ── InMemorySession ─────────────────────────────────────

    public function test_in_memory_session(): void
    {
        $session = new InMemorySession();

        $this->assertFalse($session->has('key'));
        $this->assertNull($session->get('key'));
        $this->assertSame('default', $session->get('key', 'default'));

        $session->put('key', 'value');
        $this->assertTrue($session->has('key'));
        $this->assertSame('value', $session->get('key'));

        $session->forget('key');
        $this->assertFalse($session->has('key'));
    }

    public function test_in_memory_session_regenerate(): void
    {
        $session = new InMemorySession();
        $session->put('keep', 'me');

        $oldId = $session->getId();
        $session->regenerate(false);
        $this->assertNotSame($oldId, $session->getId());
        $this->assertTrue($session->has('keep'));

        $session->regenerate(true);
        $this->assertFalse($session->has('keep'));
    }

    public function test_in_memory_session_invalidate(): void
    {
        $session = new InMemorySession();
        $session->put('data', '123');

        $oldId = $session->getId();
        $session->invalidate();
        $this->assertNotSame($oldId, $session->getId());
        $this->assertFalse($session->has('data'));
    }
}
