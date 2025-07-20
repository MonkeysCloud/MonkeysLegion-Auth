<?php
declare(strict_types=1);

namespace MonkeysLegion\Auth;

use App\Entity\User;
use MonkeysLegion\Repository\EntityRepository;
use MonkeysLegion\Repository\RepositoryFactory;
use RuntimeException;

/**
 * Service for handling user authentication, including registration and login.
 *
 * This service provides methods to register new users and authenticate existing users
 * using email and password. It uses a password hasher for secure password storage
 * and a JWT service for issuing tokens upon successful login.
 */
final class AuthService
{
    /** @var EntityRepository<User> */
    private EntityRepository $users;

    public function __construct(
        private RepositoryFactory $repoFactory,
        private PasswordHasher    $hasher,
        private JwtService        $jwt,
    ) {
        // resolve the repository for the User entity
        $this->users = $this->repoFactory->getRepository(User::class);
    }

    /**
     * Registers a new user with the given email and password.
     *
     * @param string $email The email address of the user.
     * @param string $password The password for the user.
     * @return User The newly created user entity.
     * @throws RuntimeException if the email is already registered.
     */
    public function register(string $email, string $password): User
    {
        $user = (new User)
            ->setEmail($email)
            ->setPasswordHash($this->hasher->hash($password));

        try {
            // save() populates $user->id automatically
            $this->users->save($user);
        } catch (PDOException $e) {
            // 23000 = integrity-constraint violation, 1062 = duplicate entry
            if ($e->getCode() === '23000' || $e->errorInfo[1] === 1062) {
                throw new RuntimeException('Email already registered', 409, $e);
            }
            throw $e;
        }

        return $user;
    }

    /**
     * Logs in a user with the given email and password.
     *
     * @param string $email The email address of the user.
     * @param string $password The password for the user.
     * @return string JWT token for the authenticated user.
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

        return $this->jwt->issue(['sub' => $user->getId()]);
    }
}