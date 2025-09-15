<?php
declare(strict_types=1);

namespace MonkeysLegion\Auth;

use App\Entity\User;
use MonkeysLegion\Repository\EntityRepository;
use MonkeysLegion\Repository\RepositoryFactory;
use RuntimeException;
use PDOException;

/**
 * Authentication service with:
 *  - register/login
 *  - stateless sliding ACCESS tokens (JWT, short-lived)
 *
 * No refresh-store is required. The client refreshes near expiry while active.
 */
final class AuthService
{
    private const DEFAULT_ACCESS_TTL_SEC = 1800; // 30 minutes

    /** @var EntityRepository<User> */
    private EntityRepository $users;

    public function __construct(
        private RepositoryFactory $repoFactory,
        private PasswordHasher    $hasher,
        private JwtService        $jwt,
    ) {
        $this->users = $this->repoFactory->getRepository(User::class);
    }

    /**
     * Registers a new user with the given email and password.
     *
     * @throws RuntimeException if the email is already registered.
     */
    public function register(string $email, string $password): User
    {
        $user = (new User)
            ->setEmail($email)
            ->setPasswordHash($this->hasher->hash($password));

        try {
            $this->users->save($user); // save() populates id
        } catch (PDOException $e) {
            // 23000 = integrity-constraint violation, 1062 = duplicate entry
            if ($e->getCode() === '23000' || (($e->errorInfo[1] ?? null) === 1062)) {
                throw new RuntimeException('Email already registered', 409, $e);
            }
            throw $e;
        }

        return $user;
    }

    /**
     * Logs in a user and returns a short-lived ACCESS JWT (stateless).
     *
     * @throws RuntimeException if the credentials are invalid.
     */
    public function login(string $email, string $password): string
    {
        /** @var User|null $user */
        $user = $this->users->findOneBy(['email' => $email]);
        if (! $user) {
            throw new RuntimeException('Invalid credentials');
        }

        if (! $this->hasher->verify($password, $user->getPasswordHash())) {
            throw new RuntimeException('Invalid credentials');
        }

        return $this->mintAccessTokenFor($user->getId(), self::DEFAULT_ACCESS_TTL_SEC);
    }

    /**
     * Mint a short-lived ACCESS token (JWT) for a user.
     * Adds iat/nbf/exp so the client can decode expiry.
     * Optionally includes a per-user token version if your User entity exposes getTokenVersion().
     */
    public function mintAccessTokenFor(int $userId, int $ttlSeconds = self::DEFAULT_ACCESS_TTL_SEC): string
    {
        $now = time();

        // Optional per-user token version (global revoke lever without extra tables).
        $ver = 1;
        try {
            /** @var User|null $u */
            $u = $this->users->find($userId);
            if ($u && method_exists($u, 'getTokenVersion')) {
                $maybe = (int) $u->getTokenVersion();
                if ($maybe > 0) {
                    $ver = $maybe;
                }
            }
        } catch (\Throwable) {
            // Best-effort; ignore if repository/User doesn't provide token version
        }

        $claims = [
            'sub' => $userId,
            'ver' => $ver,        // harmless if you don't use it in validation
            'iat' => $now,
            'nbf' => $now,
            'exp' => $now + $ttlSeconds,
        ];

        return $this->jwt->issue($claims);
    }

    /**
     * Re-mint an ACCESS token for an already-authenticated request (sliding sessions).
     * Call this from /auth/refresh after your middleware parsed the current token
     * and set request attribute "user_id".
     */
    public function refreshAccessForUser(int $userId, int $ttlSeconds = self::DEFAULT_ACCESS_TTL_SEC): string
    {
        return $this->mintAccessTokenFor($userId, $ttlSeconds);
    }

    /**
     * Decode a token with extra leeway for refresh operations, returning claims as an associative array.
     * This allows tokens that are just expired to be accepted within the grace period.
     *
     * @param string $token
     * @param int $graceSeconds Additional seconds of leeway to allow (beyond configured leeway)
     * @return array<string,mixed>
     * @throws RuntimeException on invalid token
     * @throws \JsonException
     */
    public function decodeForRefresh(string $token, int $graceSeconds = 600): array
    {
        // Delegate to JwtService so we keep verification in one place
        return $this->jwt->decodeWithExtraLeeway($token, $graceSeconds);
    }
}
