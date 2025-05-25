# MonkeysLegion Auth & JWT

A drop-in authentication and authorization scaffolding for MonkeysLegion.  
Provides:

- **Password hashing** (bcrypt via `PasswordHasher`)
- **JWT issuance & verification** (`JwtService`)
- **User registration & login** (`AuthService`)
- **PSR-15 middleware** to authenticate routes (`JwtAuthMiddleware`)
- **Attribute-based authorization** (`#[Can]`) and policies
- **Helper functions** (`auth_check()`, `auth_user_id()`) for templates

---

## 📦 Installation

```bash
composer require monkeyscloud/monkeyslegion-auth:^1.0@dev
```
Ensure your composer.json autoloads:
```json
"autoload": {
  "psr-4": {
    "MonkeysLegion\\Auth\\": "src/"
  }
}
```
Then:
```bash
composer dump-autoload
```
## 🛠️ Configuration
Register services in your DI container (config/app.php):
```php
use MonkeysLegion\Auth\PasswordHasher;
use MonkeysLegion\Auth\JwtService;
use MonkeysLegion\Auth\AuthService;
use MonkeysLegion\Auth\Middleware\JwtAuthMiddleware;
use MonkeysLegion\Auth\Middleware\AuthorizationMiddleware;
use MonkeysLegion\AuthService\AuthorizationService;

// Password hashing & JWT
PasswordHasher::class => fn() => new PasswordHasher(),

JwtService::class => fn($c) => new JwtService(
    $c->get(MonkeysLegion\Mlc\Config::class)->get('auth.jwt_secret'),
    (int)$c->get(MonkeysLegion\Mlc\Config::class)->get('auth.jwt_ttl', 3600)
),

AuthService::class => fn($c) => new AuthService(
    $c->get(App\Repository\UserRepository::class),
    $c->get(PasswordHasher::class),
    $c->get(JwtService::class)
),

// Authentication middleware
JwtAuthMiddleware::class => fn($c) => new JwtAuthMiddleware(
    $c->get(JwtService::class),
    $c->get(Psr\Http\Message\ResponseFactoryInterface::class)
),

// Authorization service & middleware
AuthorizationService::class => fn() => tap(new AuthorizationService(), function($svc) {
    $svc->registerPolicy(App\Entity\Post::class, App\Policy\PostPolicy::class);
    // register more policies here...
}),

AuthorizationMiddleware::class => fn($c) => new AuthorizationMiddleware(
    $c->get(AuthorizationService::class)
),
```
Add both middleware to your HTTP pipeline:
```php
[
  /* ... other middleware ... */
  $c->get(JwtAuthMiddleware::class),
  $c->get(AuthorizationMiddleware::class),
],
```
## 🧩 Usage
### Registration
```php
// in a controller action
$email    = $request->getParsedBody()['email'];
$password = $request->getParsedBody()['password'];

$user = $container
    ->get(AuthService::class)
    ->register($email, $password);

// $user is your App\Entity\User instance
```
### Login & Token
```php
$token = $container
    ->get(AuthService::class)
    ->login($email, $password);

// return JSON with token
return new JsonResponse(['token' => $token]);
```
### Protecting Endpoints
Send the JWT in an Authorization: Bearer {token} header.
The JwtAuthMiddleware will decode & verify and inject userId into request attributes.

In your controllers you can then retrieve:

```php
$userId = $request->getAttribute('userId');
```

## 🛡️ Attribute-Based Authorization
Use the #[Can] attribute on your controller methods (or classes) to enforce abilities via your registered policies:
```php
use MonkeysLegion\Auth\Attributes\Can;

final class PostController
{
    #[Can('edit', App\Entity\Post::class)]
    public function edit(ServerRequestInterface $req): ResponseInterface
    {
        $post = /* load post by id from repository */;
        // if unauthorized, middleware will have thrown
        // now handle the edit…
    }
}
```
- Policies live in App\Policy\*Policy.php and implement PolicyInterface.
- The before hook can short-circuit (e.g. admin users).
- Then your ability method (e.g. edit($user, $post)) decides.

## 🖋 Template Helpers
Add to your MLView helpers (e.g. src/Template/helpers.php):
```php
if (! function_exists('auth_user_id')) {
    function auth_user_id(): ?int {
        $req = ML_CONTAINER->get(Psr\Http\Message\ServerRequestInterface::class);
        return $req->getAttribute('userId');
    }
}
if (! function_exists('auth_check')) {
    function auth_check(): bool {
        return auth_user_id() !== null;
    }
}
```

Then in your views:
```html
@if(auth_check())
  <p>Welcome back, user #{{ auth_user_id() }}!</p>
@else
  <p>Please <a href="/login">log in</a>.</p>
@endif
```

## ⚙️ Extending
- Remember-me: add long-lived cookies & DB tokens.
- Password reset: generate time-bound tokens, email links, reset form.
- Additional abilities: register more policies and use #[Can] on routes or methods.

## 📝 License
MIT © 2025 MonkeysCloud