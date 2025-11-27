# MonkeysLegion Auth

[![PHP Version](https://img.shields.io/badge/php-%3E%3D8.4-8892BF.svg)](https://php.net/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![PSR-7](https://img.shields.io/badge/PSR-7-blue.svg)](https://www.php-fig.org/psr/psr-7/)
[![PSR-15](https://img.shields.io/badge/PSR-15-blue.svg)](https://www.php-fig.org/psr/psr-15/)

A comprehensive, production-ready PHP authentication and authorization package for modern applications.

---

## ✨ Features

| Feature | Description |
|---------|-------------|
| **JWT Authentication** | Stateless auth with access/refresh token pairs and automatic rotation |
| **RBAC** | Role-based access control with permission inheritance and wildcards |
| **2FA/TOTP** | Two-factor authentication compatible with Google Authenticator, Authy, 1Password |
| **OAuth2** | Social login with Google, GitHub (easily extensible for more providers) |
| **API Keys** | Scoped API keys for machine-to-machine authentication |
| **Rate Limiting** | Brute force protection with Redis, cache, or in-memory backends |
| **Token Revocation** | Blacklist tokens instantly with Redis or database storage |
| **Policy-Based Auth** | Laravel-style policies for fine-grained authorization |
| **Event System** | PSR-14 compatible events for audit logging and integrations |
| **Custom Exceptions** | Rich exception hierarchy with context for better error handling |

---

## 📋 Requirements

- PHP 8.4 or higher
- [firebase/php-jwt](https://github.com/firebase/php-jwt) ^6.10
- PSR-7 HTTP Message implementation (e.g., `nyholm/psr7`)
- PSR-15 HTTP Server Middleware support
- **Optional:** Redis extension for production rate limiting/token storage

---

## 📦 Installation

```bash
composer require monkeyscloud/monkeyslegion-auth
```

---

## 🚀 Quick Start

### 1. Basic Authentication Setup

```php
<?php

use MonkeysLegion\Auth\Service\AuthService;
use MonkeysLegion\Auth\Service\JwtService;
use MonkeysLegion\Auth\Service\PasswordHasher;

// Initialize services
$jwt = new JwtService(
    secret: $_ENV['JWT_SECRET'],      // Min 32 characters
    accessTtl: 1800,                   // 30 minutes
    refreshTtl: 604800,                // 7 days
    issuer: 'your-app',                // Optional
);

$auth = new AuthService(
    users: $userProvider,              // Your UserProviderInterface implementation
    hasher: new PasswordHasher(),
    jwt: $jwt,
    tokenStorage: $redisTokenStorage,  // Optional: for token blacklisting
    rateLimiter: $rateLimiter,         // Optional: for brute force protection
);
```

### 2. User Login

```php
try {
    $result = $auth->login($email, $password, $request->ip());
    
    if ($result->requires2FA) {
        // Store challenge token in session, show 2FA form
        return response()->json([
            'requires_2fa' => true,
            'challenge' => $result->challengeToken,
        ]);
    }
    
    // Success! Return tokens to client
    return response()->json([
        'access_token' => $result->tokens->accessToken,
        'refresh_token' => $result->tokens->refreshToken,
        'expires_at' => $result->tokens->accessExpiresAt,
    ]);
    
} catch (InvalidCredentialsException $e) {
    return response()->json(['error' => 'Invalid credentials'], 401);
} catch (AccountLockedException $e) {
    return response()->json([
        'error' => 'Account locked',
        'retry_after' => $e->getLockedUntil() - time(),
    ], 423);
}
```

### 3. Token Refresh

```php
try {
    $tokens = $auth->refresh($refreshToken);
    
    return response()->json([
        'access_token' => $tokens->accessToken,
        'refresh_token' => $tokens->refreshToken,  // Rotated!
        'expires_at' => $tokens->accessExpiresAt,
    ]);
} catch (TokenRevokedException $e) {
    return response()->json(['error' => 'Session expired'], 401);
}
```

### 4. Logout

```php
// Single device
$auth->logout($accessToken);

// All devices (invalidates all tokens)
$auth->logout($accessToken, allDevices: true);
```

---

## 👤 User Entity Setup

Implement the required interfaces using the provided traits:

```php
<?php

use MonkeysLegion\Auth\Contract\AuthenticatableInterface;
use MonkeysLegion\Auth\Contract\HasRolesInterface;
use MonkeysLegion\Auth\Contract\HasPermissionsInterface;
use MonkeysLegion\Auth\Trait\AuthenticatableTrait;
use MonkeysLegion\Auth\Trait\HasRolesTrait;
use MonkeysLegion\Auth\Trait\HasPermissionsTrait;

class User implements AuthenticatableInterface, HasRolesInterface, HasPermissionsInterface
{
    use AuthenticatableTrait;
    use HasRolesTrait;
    use HasPermissionsTrait;

    public function __construct(
        public readonly int $id,
        public string $email,
        public string $passwordHash,
        public int $tokenVersion = 1,
        public bool $emailVerified = false,
        public ?string $twoFactorSecret = null,
        public array $roles = [],
        public array $permissions = [],
    ) {}

    // Required by AuthenticatableInterface
    public function getAuthIdentifier(): int|string
    {
        return $this->id;
    }

    public function getAuthPassword(): string
    {
        return $this->passwordHash;
    }

    public function getTokenVersion(): int
    {
        return $this->tokenVersion;
    }
}
```

---

## 🛡️ Middleware

### Authentication Middleware

Validates JWT tokens and attaches user to request:

```php
use MonkeysLegion\Auth\Middleware\AuthenticationMiddleware;

$middleware = new AuthenticationMiddleware(
    auth: $authService,
    users: $userProvider,
    publicPaths: [
        '/auth/*',           // Wildcard matching
        '/public/*',
        '/health',           // Exact match
        '/api/*/public',     // Glob patterns
    ],
);

// In your middleware stack
$app->pipe($middleware);
```

### Authorization Middleware

Enforces `#[RequiresRole]`, `#[RequiresPermission]`, and `#[Can]` attributes:

```php
use MonkeysLegion\Auth\Middleware\AuthorizationMiddleware;

$middleware = new AuthorizationMiddleware(
    authorization: $authorizationService,
    permissions: $permissionChecker,
    publicPaths: ['/auth/*'],
);
```

### Rate Limit Middleware

```php
use MonkeysLegion\Auth\Middleware\RateLimitMiddleware;

$middleware = new RateLimitMiddleware(
    limiter: $rateLimiter,
    defaultMaxAttempts: 60,
    defaultDecaySeconds: 60,
);
```

---

## 🏷️ PHP Attributes

Secure your controllers with declarative attributes:

```php
<?php

use MonkeysLegion\Auth\Attribute\Authenticated;
use MonkeysLegion\Auth\Attribute\RequiresRole;
use MonkeysLegion\Auth\Attribute\RequiresPermission;
use MonkeysLegion\Auth\Attribute\Can;

#[Authenticated]  // All methods require authentication
class PostController
{
    // Anyone authenticated can list
    public function index(): Response
    {
        return $this->posts->paginate();
    }

    #[RequiresPermission('posts.create')]
    public function create(Request $request): Response
    {
        // Only users with posts.create permission
    }

    #[Can('update', Post::class)]  // Policy-based
    public function update(Post $post, Request $request): Response
    {
        // Checked against PostPolicy::update()
    }

    #[RequiresRole('admin', 'moderator')]  // Any of these roles
    public function delete(Post $post): Response
    {
        // Only admins or moderators
    }
}
```

---

## 👑 RBAC (Role-Based Access Control)

### Define Roles

```php
use MonkeysLegion\Auth\RBAC\RoleRegistry;
use MonkeysLegion\Auth\RBAC\PermissionChecker;

$roles = new RoleRegistry();

$roles->registerFromConfig([
    'super-admin' => [
        'permissions' => ['*'],                    // Full access
        'description' => 'Complete system control',
    ],
    'admin' => [
        'permissions' => ['users.*', 'posts.*', 'settings.view'],
        'description' => 'Administrative access',
    ],
    'editor' => [
        'permissions' => ['posts.*', 'media.*'],
        'inherits' => ['viewer'],                  // Inheritance!
    ],
    'author' => [
        'permissions' => ['posts.create', 'posts.edit-own', 'posts.delete-own'],
        'inherits' => ['viewer'],
    ],
    'viewer' => [
        'permissions' => ['posts.view', 'media.view'],
    ],
]);

$checker = new PermissionChecker($roles);
```

### Check Permissions

```php
// Single permission
if ($checker->can($user, 'posts.create')) {
    // Allowed
}

// Wildcard matching: 'posts.*' grants 'posts.anything'
if ($checker->can($user, 'posts.publish')) {
    // Allowed for users with 'posts.*'
}

// Check role
if ($checker->hasRole($user, 'admin')) {
    // User is admin
}

// Any of multiple roles
if ($checker->hasAnyRole($user, ['admin', 'editor'])) {
    // User has at least one
}

// All permissions required
if ($checker->hasAllPermissions($user, ['posts.edit', 'posts.publish'])) {
    // User has both
}
```

---

## 🔐 Two-Factor Authentication (2FA)

### Setup 2FA for User

```php
use MonkeysLegion\Auth\TwoFactor\TotpProvider;
use MonkeysLegion\Auth\Service\TwoFactorService;

$totp = new TotpProvider();
$twoFactor = new TwoFactorService($totp, issuer: 'YourApp');

// Step 1: Generate setup data
$setup = $twoFactor->generateSetup($user->email);

return response()->json([
    'secret' => $setup['secret'],           // For manual entry
    'qr_code' => $setup['qr_code'],          // Base64 QR image
    'provisioning_uri' => $setup['uri'],     // otpauth:// URI
    'recovery_codes' => $setup['recovery'],  // Save these!
]);
```

### Enable 2FA (Verify First Code)

```php
// Step 2: User scans QR and enters code
try {
    $twoFactor->enable(
        secret: $setup['secret'],
        code: $request->input('code'),
        userId: $user->id,
    );
    
    return response()->json(['message' => '2FA enabled']);
} catch (TwoFactorInvalidException $e) {
    return response()->json(['error' => 'Invalid code'], 400);
}
```

### Login with 2FA

```php
// After password verification, if 2FA required:
$result = $auth->login($email, $password);

if ($result->requires2FA) {
    // Store challenge token, show 2FA form
    $_SESSION['2fa_challenge'] = $result->challengeToken;
    return view('auth.2fa');
}

// Later, verify 2FA code:
$result = $auth->verify2FA(
    challengeToken: $_SESSION['2fa_challenge'],
    code: $request->input('code'),
);

// Success! $result->tokens contains JWT tokens
```

### Recovery Codes

```php
// Use recovery code instead of TOTP
$valid = $twoFactor->verifyRecoveryCode($user->id, $recoveryCode);

if ($valid) {
    // Code is consumed (one-time use)
    // Proceed with login
}

// Regenerate recovery codes
$newCodes = $twoFactor->regenerateRecoveryCodes($user->id);
```

---

## 🌐 OAuth2 / Social Login

### Setup Providers

```php
use MonkeysLegion\Auth\OAuth\OAuthService;
use MonkeysLegion\Auth\OAuth\GoogleProvider;
use MonkeysLegion\Auth\OAuth\GitHubProvider;

$oauth = new OAuthService();

$oauth->register(new GoogleProvider(
    clientId: $_ENV['GOOGLE_CLIENT_ID'],
    clientSecret: $_ENV['GOOGLE_CLIENT_SECRET'],
    redirectUri: 'https://yourapp.com/auth/google/callback',
));

$oauth->register(new GitHubProvider(
    clientId: $_ENV['GITHUB_CLIENT_ID'],
    clientSecret: $_ENV['GITHUB_CLIENT_SECRET'],
    redirectUri: 'https://yourapp.com/auth/github/callback',
));
```

### Redirect to Provider

```php
// Generate state for CSRF protection
$state = $oauth->generateState();
$_SESSION['oauth_state'] = $state;

// Get authorization URL
$url = $oauth->getAuthorizationUrl('google', $state, [
    'additional_scope',  // Optional extra scopes
]);

return redirect($url);
```

### Handle Callback

```php
// Verify state
if ($request->get('state') !== $_SESSION['oauth_state']) {
    throw new InvalidStateException();
}

// Exchange code for user info
$oauthUser = $oauth->handleCallback('google', $request->get('code'));

// $oauthUser contains:
// - providerId: string (provider's user ID)
// - email: string
// - name: ?string
// - avatar: ?string

// Find or create user
$user = $userRepository->findByEmail($oauthUser->email)
    ?? $userRepository->createFromOAuth($oauthUser);

// Issue tokens
$tokens = $auth->issueTokenPair($user);
```

### Add Custom Provider

```php
use MonkeysLegion\Auth\OAuth\AbstractOAuthProvider;

class MicrosoftProvider extends AbstractOAuthProvider
{
    public function getName(): string
    {
        return 'microsoft';
    }

    protected function getAuthorizationEndpoint(): string
    {
        return 'https://login.microsoftonline.com/common/oauth2/v2.0/authorize';
    }

    protected function getTokenEndpoint(): string
    {
        return 'https://login.microsoftonline.com/common/oauth2/v2.0/token';
    }

    protected function getUserInfoEndpoint(): string
    {
        return 'https://graph.microsoft.com/v1.0/me';
    }

    protected function getDefaultScopes(): array
    {
        return ['openid', 'email', 'profile'];
    }

    protected function parseUserInfo(array $data): array
    {
        return [
            'id' => $data['id'],
            'email' => $data['mail'] ?? $data['userPrincipalName'],
            'name' => $data['displayName'],
            'avatar' => null,
        ];
    }
}
```

---

## 🔑 API Keys

For machine-to-machine authentication:

### Create API Key

```php
use MonkeysLegion\Auth\ApiKey\ApiKeyService;

$apiKeys = new ApiKeyService($apiKeyRepository);

$result = $apiKeys->create(
    userId: $user->id,
    name: 'Production Server',
    scopes: ['read:users', 'write:posts'],  // Or ['*'] for full access
    expiresAt: new DateTime('+1 year'),      // Optional
);

// ⚠️ Show key ONCE - it cannot be retrieved later!
return response()->json([
    'key' => $result['key'],  // ml_abc123def456_secretpart789
    'id' => $result['id'],
    'name' => $result['name'],
]);
```

### Validate API Key

```php
// In middleware or controller
$apiKey = $request->getHeaderLine('X-API-Key');

$keyData = $apiKeys->validate($apiKey);

if (!$keyData) {
    throw new InvalidApiKeyException();
}

// Check scopes
if (!$apiKeys->hasScope($keyData, 'write:posts')) {
    throw new ForbiddenException('Insufficient scope');
}

// Use $keyData['user_id'] for attribution
```

### Manage Keys

```php
// List user's keys
$keys = $apiKeys->listForUser($user->id);

// Revoke a key
$apiKeys->revoke($keyId, $user->id);

// Key format: ml_{keyId}_{secret}
// Only keyId is stored; secret is hashed
```

---

## ⏱️ Rate Limiting

### Available Backends

```php
use MonkeysLegion\Auth\RateLimit\RedisRateLimiter;
use MonkeysLegion\Auth\RateLimit\CacheRateLimiter;
use MonkeysLegion\Auth\RateLimit\InMemoryRateLimiter;

// Redis (recommended for production)
$limiter = new RedisRateLimiter($redis);

// PSR-16 Cache
$limiter = new CacheRateLimiter($cache);

// In-memory (for testing/single-server)
$limiter = new InMemoryRateLimiter();
```

### Manual Rate Limiting

```php
$key = 'login:' . $request->ip();

if (!$limiter->attempt($key, maxAttempts: 5, decaySeconds: 900)) {
    $retryAfter = $limiter->availableIn($key);
    
    throw new RateLimitException(
        message: 'Too many login attempts',
        retryAfter: $retryAfter,
    );
}

// On successful login, clear the limit
$limiter->clear($key);
```

### Per-Route Rate Limits

Configure different limits per endpoint:

```php
$middleware = new RateLimitMiddleware(
    limiter: $limiter,
    defaultMaxAttempts: 60,
    defaultDecaySeconds: 60,
    limits: [
        'POST /auth/login' => ['max' => 5, 'decay' => 900],
        'POST /auth/register' => ['max' => 3, 'decay' => 3600],
        'POST /auth/forgot-password' => ['max' => 3, 'decay' => 3600],
        'POST /api/*' => ['max' => 100, 'decay' => 60],
    ],
);
```

---

## 📜 Policies

Fine-grained authorization for model actions:

### Define a Policy

```php
use MonkeysLegion\Auth\Policy\AbstractPolicy;

class PostPolicy extends AbstractPolicy
{
    /**
     * Runs before all checks. Return true/false to override, null to continue.
     */
    public function before(?object $user, string $ability, ?object $model = null): ?bool
    {
        // Admins can do anything
        if ($user?->hasRole('admin')) {
            return true;
        }
        return null;  // Continue to specific check
    }

    public function view(?object $user, Post $post): bool
    {
        // Anyone can view published posts
        if ($post->isPublished()) {
            return true;
        }
        // Only author can view drafts
        return $user?->id === $post->authorId;
    }

    public function create(?object $user): bool
    {
        // Any authenticated user
        return $user !== null;
    }

    public function update(?object $user, Post $post): bool
    {
        return $user?->id === $post->authorId;
    }

    public function delete(?object $user, Post $post): bool
    {
        return $user?->id === $post->authorId;
    }

    public function publish(?object $user, Post $post): bool
    {
        return $user?->id === $post->authorId 
            && $user->hasPermission('posts.publish');
    }
}
```

### Register and Use

```php
use MonkeysLegion\Auth\Policy\Gate;

$gate = new Gate();
$gate->policy(Post::class, PostPolicy::class);

// Check authorization
if ($gate->allows($user, 'update', $post)) {
    // Allowed
}

// Or throw on denied
$gate->authorize($user, 'delete', $post);  // Throws UnauthorizedException

// Define inline abilities
$gate->define('access-admin', fn(?object $user) => $user?->hasRole('admin'));

if ($gate->allows($user, 'access-admin')) {
    // Show admin panel
}
```

---

## 📡 Events

All events extend `AuthEvent` and are dispatched via PSR-14:

| Event | When Fired | Key Properties |
|-------|------------|----------------|
| `UserRegistered` | New user created | `user`, `ipAddress` |
| `LoginSucceeded` | Successful login | `user`, `ipAddress`, `userAgent` |
| `LoginFailed` | Failed login | `identifier`, `reason`, `ipAddress` |
| `Logout` | User logged out | `userId`, `allDevices` |
| `TokenRefreshed` | Token refreshed | `userId`, `ipAddress` |
| `PasswordChanged` | Password updated | `userId` |
| `PasswordResetRequested` | Reset requested | `userId`, `email` |
| `TwoFactorEnabled` | 2FA turned on | `userId` |
| `TwoFactorDisabled` | 2FA turned off | `userId` |

### Listen to Events

```php
// Using PSR-14 dispatcher
$dispatcher->listen(LoginFailed::class, function (LoginFailed $event) {
    Log::warning('Failed login attempt', [
        'email' => $event->identifier,
        'ip' => $event->ipAddress,
        'reason' => $event->reason,
        'time' => $event->occurredAt->format('c'),
    ]);
    
    // Alert on suspicious activity
    if ($this->isSuspicious($event)) {
        $this->alertSecurityTeam($event);
    }
});

$dispatcher->listen(LoginSucceeded::class, function (LoginSucceeded $event) {
    // Update last login timestamp
    $this->users->updateLastLogin($event->user->id, $event->occurredAt);
    
    // Send notification for new device
    if ($this->isNewDevice($event)) {
        $this->notifyUser($event->user, 'New device login detected');
    }
});
```

---

## ❌ Exception Hierarchy

All exceptions provide rich context for error handling:

```
AuthException (401)
├── InvalidCredentialsException (401)
├── TokenExpiredException (401)
├── TokenInvalidException (401)
├── TokenRevokedException (401)
├── TwoFactorInvalidException (401)
├── InvalidApiKeyException (401)
├── UnauthorizedException (403)
├── ForbiddenException (403)
├── EmailNotVerifiedException (403)
├── TwoFactorRequiredException (428)
├── AccountLockedException (423)
├── RateLimitException (429)
├── UserAlreadyExistsException (409)
└── PolicyNotFoundException (500)
```

### Error Handling

```php
try {
    $result = $auth->login($email, $password);
} catch (AuthException $e) {
    return response()->json(
        $e->toArray(),  // Structured error response
        $e->getCode(),
    );
}

// toArray() returns:
// [
//     'error' => true,
//     'type' => 'InvalidCredentialsException',
//     'message' => 'Invalid credentials',
//     'code' => 401,
//     'context' => [...],
// ]
```

---

## 🗄️ Database Schema

### Required Tables

```sql
-- Users (extend as needed)
CREATE TABLE users (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    email VARCHAR(255) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    token_version INT UNSIGNED DEFAULT 1,
    email_verified_at TIMESTAMP NULL,
    two_factor_secret VARCHAR(255) NULL,
    two_factor_recovery_codes JSON NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);

-- Roles
CREATE TABLE roles (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(100) NOT NULL UNIQUE,
    description VARCHAR(255) NULL,
    permissions JSON NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- User Roles (many-to-many)
CREATE TABLE user_roles (
    user_id BIGINT UNSIGNED NOT NULL,
    role_id BIGINT UNSIGNED NOT NULL,
    PRIMARY KEY (user_id, role_id),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE CASCADE
);

-- API Keys
CREATE TABLE api_keys (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    user_id BIGINT UNSIGNED NOT NULL,
    name VARCHAR(255) NOT NULL,
    key_id VARCHAR(32) NOT NULL UNIQUE,
    key_hash VARCHAR(255) NOT NULL,
    scopes JSON NOT NULL,
    last_used_at TIMESTAMP NULL,
    expires_at TIMESTAMP NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    INDEX idx_key_id (key_id)
);

-- OAuth Accounts
CREATE TABLE oauth_accounts (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    user_id BIGINT UNSIGNED NOT NULL,
    provider VARCHAR(50) NOT NULL,
    provider_user_id VARCHAR(255) NOT NULL,
    access_token TEXT NULL,
    refresh_token TEXT NULL,
    expires_at TIMESTAMP NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    UNIQUE INDEX idx_provider_user (provider, provider_user_id)
);

-- Token Blacklist (if not using Redis)
CREATE TABLE token_blacklist (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    token_id VARCHAR(64) NOT NULL UNIQUE,
    expires_at TIMESTAMP NOT NULL,
    INDEX idx_expires (expires_at)
);

-- Password Resets
CREATE TABLE password_resets (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    user_id BIGINT UNSIGNED NOT NULL,
    token_hash VARCHAR(255) NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    INDEX idx_expires (expires_at)
);
```

---

## 🧪 Testing

```bash
# Install dependencies
composer install

# Run all tests
composer test

# Run specific test suites
composer test:unit
composer test:integration

# Generate coverage report
composer test:coverage

# Static analysis
composer phpstan

# Code style check
composer cs
composer cs-fix  # Auto-fix
```

### Test Fixtures

The package includes test doubles for easy testing:

```php
use MonkeysLegion\Auth\Tests\Fixtures\FakeUser;
use MonkeysLegion\Auth\Tests\Fixtures\FakeUserProvider;
use MonkeysLegion\Auth\Tests\Fixtures\FakeTokenStorage;
use MonkeysLegion\Auth\Tests\Fixtures\FakeRequest;

// In your tests
$users = new FakeUserProvider();
$users->addUser(new FakeUser(
    id: 1,
    email: 'test@example.com',
    roles: ['admin'],
));

$auth = new AuthService(
    users: $users,
    hasher: new PasswordHasher(),
    jwt: new JwtService('test-secret-32-characters-long'),
    tokenStorage: new FakeTokenStorage(),
);
```

---

## 🔒 Security Best Practices

1. **Use strong JWT secrets** — Minimum 256 bits (32+ characters) of cryptographic randomness
2. **Keep access tokens short-lived** — 15-30 minutes recommended
3. **Always rotate refresh tokens** — Blacklist old tokens on refresh
4. **Enable rate limiting** — Especially on authentication endpoints
5. **Require 2FA for privileged accounts** — Admins, financial access, etc.
6. **Validate token versions** — Increment on password change/security events
7. **Store only hashed secrets** — API keys, recovery codes, etc.
8. **Use HTTPS exclusively** — Never transmit tokens over HTTP
9. **Implement proper CORS** — Restrict token usage to your domains
10. **Monitor authentication events** — Log and alert on suspicious activity

---

## 📄 License

MIT License — see [LICENSE](LICENSE) for details.

---

## 🤝 Contributing

Contributions are welcome! Please read our contributing guidelines and submit pull requests to the `main` branch.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Write tests for your changes
4. Ensure all tests pass (`composer check`)
5. Commit your changes (`git commit -m 'Add amazing feature'`)
6. Push to the branch (`git push origin feature/amazing-feature`)
7. Open a Pull Request

---

<p align="center">
  Built with ❤️ by <a href="https://monkeyslegion.com">MonkeysLegion</a>
</p>
