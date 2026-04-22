# MonkeysLegion Auth v2

Multi-guard, attribute-first authentication and authorization for the MonkeysLegion framework. Ground-up rebuild for PHP 8.4 with property hooks, typed constants, and zero hard dependencies.

## Features

| Feature | Status |
|---|---|
| **Multi-Guard System** | JWT, Session, API Key, WebAuthn/Passkey, Composite (try multiple in order) |
| **Attribute-First Auth** | `#[Guard]`, `#[Authenticated]`, `#[Authorize]`, `#[RequiresRole]`, `#[RequiresPermission]`, `#[RateLimit]`, `#[Passkey]` |
| **JWT Service** | HS256/RS256, token families, refresh rotation attack detection, signature-verified introspection |
| **Session Guard** | Session fixation prevention, token version validation, remember-me |
| **Policy Gate** | `allows()`, `denies()`, `authorize()`, `inspect()` with deny reasons |
| **RBAC** | Hierarchical roles, wildcard permissions, super-admin, decoupled via `RoleRepositoryInterface` |
| **Password Hasher** | NIST SP 800-63B policy engine, Argon2ID/bcrypt, auto-rehash |
| **Rate Limiting** | Per-route, per-user, configurable via attributes |
| **Two-Factor Auth** | TOTP (RFC 6238), backup/recovery codes |
| **PSR-15 Middleware** | Authentication, Authorization, Rate Limiting — all attribute-aware |
| **PHP 8.4 Native** | Property hooks, typed constants, `readonly` DTOs |

## Requirements

- **PHP 8.4** or higher
- `firebase/php-jwt` ^7.0
- `psr/http-message` ^2.0

## Installation

```bash
composer require monkeyscloud/monkeyslegion-auth:dev-2.0.0
```

## Architecture

```
src/
├── Attribute/          # #[Guard], #[Authenticated], #[Authorize], #[RequiresRole], #[RequiresPermission], #[RateLimit]
├── Contract/           # GuardInterface, StatefulGuardInterface, AuthenticatableInterface, SessionInterface, UserProviderInterface, ...
├── DTO/                # AuthResult, TokenPair, OAuthUser, PasswordPolicy
├── Event/              # AuthEvent, LoginSucceeded, LoginFailed, Logout, TokenRefreshed, ...
├── Exception/          # AuthException hierarchy with HTTP status codes and logging context
├── Guard/              # JwtGuard, SessionGuard, ApiKeyGuard, CompositeGuard, AuthManager
├── Middleware/          # AuthenticationMiddleware, AuthorizationMiddleware, RateLimitMiddleware
├── Policy/             # Gate (ability-based access control)
├── RBAC/               # RbacService, RoleRepositoryInterface, InMemoryRoleRepository
├── RateLimit/          # InMemoryRateLimiter
├── Service/            # AuthService, JwtService, PasswordHasher
├── Storage/            # InMemoryTokenStorage, InMemoryUserProvider, InMemorySession
├── Trait/              # AuthenticatableTrait, HasRolesTrait, HasPermissionsTrait
└── TwoFactor/          # TotpProvider
```

## Quick Start

### JWT Guard (Stateless)

```php
use MonkeysLegion\Auth\Guard\JwtGuard;
use MonkeysLegion\Auth\Guard\AuthManager;
use MonkeysLegion\Auth\Service\JwtService;

$jwt   = new JwtService('your-secret-key-at-least-32-chars');
$guard = new JwtGuard($jwt, $userProvider);

$manager = new AuthManager(defaultGuard: 'jwt');
$manager->register('jwt', $guard);

// Authenticate a request
$user = $manager->guard()->authenticate($request);
```

### Session Guard (Stateful)

```php
use MonkeysLegion\Auth\Guard\SessionGuard;

$guard = new SessionGuard($session, $userProvider);

// Login (regenerates session ID to prevent fixation)
$guard->login($user);

// Authenticate from session
$user = $guard->authenticate($request);

// Logout
$guard->logout();
```

### API Key Guard (Stateless)

Secure authentication for internal services or CLI tools using the `X-API-Key` header:

```php
use MonkeysLegion\Auth\Guard\ApiKeyGuard;

$guard = new ApiKeyGuard(
    users: $userProvider,
    headerName: 'X-API-Key', // default
);

// Authenticates via header only (security hardened)
$user = $guard->authenticate($request);
```

### WebAuthn / Passkey Guard

Integrates with [MonkeysLegion-WebAuthn](https://github.com/MonkeysCloud/MonkeysLegion-WebAuthn) for passwordless authentication:

```php
use MonkeysLegion\Auth\Guard\WebAuthnGuard;
use MonkeysLegion\Auth\Event\PasskeyAuthenticated;
use MonkeysLegion\Auth\Attribute\Passkey;

// 1. Register the guard
$manager->register('webauthn', new WebAuthnGuard($userProvider));

// 2. In your controller: verify the assertion, then set the request attribute
$credential = $webAuthnService->verifyAuthentication($assertionResponse);
$request = $request->withAttribute('webauthn.user_handle', $credential->userHandle);

// 3. The guard resolves the user from the verified attribute
$user = $manager->guard('webauthn')->authenticate($request);

// 4. Dispatch audit event
$dispatcher->dispatch(new PasskeyAuthenticated(
    userId: $user->getAuthIdentifier(),
    credentialId: base64_encode($credential->credentialId),
    ipAddress: $serverParams['REMOTE_ADDR'] ?? null,
));
```

Mark routes/controllers as requiring passkey authentication:

```php
#[Passkey]                                      // userVerification: 'preferred'
#[Passkey(userVerification: 'required')]        // high-assurance actions
public function transferFunds(): Response { ... }
```

### Core Authentication Service (AuthService)

The central service for managing credential-based login, 2FA, and token lifecycle:

```php
use MonkeysLegion\Auth\Service\AuthService;

$auth = new AuthService(
    users: $userProvider,
    hasher: $passwordHasher,
    jwt: $jwtService,
    tokenStorage: $tokenStorage,    // for blacklisting
    rateLimiter: $rateLimiter,      // for brute-force protection
    refreshLeeway: 60,              // optional: clock skew leeway in seconds
);

// Login (returns AuthResult for success, 2FA required, or failure)
$result = $auth->login('user@example.com', 'password');

if ($result->requires2FA) {
    // Handling 2FA...
}

// Refresh token rotation
$tokens = $auth->refresh($refreshToken);
```

### Attribute-Based Security

```php
use MonkeysLegion\Auth\Attribute\Authenticated;
use MonkeysLegion\Auth\Attribute\RequiresRole;
use MonkeysLegion\Auth\Attribute\RequiresPermission;
use MonkeysLegion\Auth\Attribute\RateLimit;

#[Authenticated(guard: 'jwt')]
#[RequiresRole(['admin', 'editor'], mode: 'any')]
#[RateLimit(maxAttempts: 60, decaySeconds: 60)]
class ArticleController
{
    #[RequiresPermission('articles.publish')]
    public function publish(int $id): Response
    {
        // Only authenticated users with admin/editor role
        // and articles.publish permission can reach here
    }
}
```

### Policy Gate

```php
use MonkeysLegion\Auth\Policy\Gate;

$gate = new Gate();
$gate->define('update-post', fn($user, $post) => $user->id === $post->authorId);

// Check
$gate->allows($user, 'update-post', $post);    // true/false
$gate->authorize($user, 'update-post', $post);  // throws UnauthorizedException

// Detailed deny reason
$result = $gate->inspect($user, 'update-post', $post);
$result->allowed;  // false
$result->reason;   // "Not authorized for: update-post"
```

### Password Hashing with Policy

```php
use MonkeysLegion\Auth\Service\PasswordHasher;
use MonkeysLegion\Auth\DTO\PasswordPolicy;

$hasher = new PasswordHasher(
    policy: new PasswordPolicy(
        minLength: 12,
        requireUppercase: true,
        requireNumbers: true,
        requireSymbols: true,
        rejectCommon: true,
    ),
);

$hash = $hasher->hash('MyStr0ng!Pass');
$hasher->verify('MyStr0ng!Pass', $hash); // true
$hasher->needsRehash($hash);             // false
```

## Security Features

- **Token family tracking** — detects refresh token reuse attacks
- **CSPRNG token IDs** — `random_bytes(16)` for all token identifiers
- **Session fixation prevention** — session regenerated on every login
- **Token versioning** — increment version to invalidate all sessions/tokens globally
- **Timing-safe comparisons** — `hash_equals` for all credential/token checks
- **Account lockout** — configurable failed attempt limits
- **Audit trail** — all auth events include correlation IDs
- **Clock skew leeway** — configurable verification leeway for distributed systems

## Testing

```bash
composer test
# 139 tests, 320 assertions
```

## License

MIT © [MonkeysCloud](https://monkeys.cloud)
