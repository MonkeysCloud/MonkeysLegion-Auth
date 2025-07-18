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
        /** @var User|null $existing */
        $existing = $this->users->findOneBy(['email' => $email]);
        if ($existing) {
            throw new RuntimeException('Email already registered');
        }

        $user = new User();
        $user->setEmail($email);
        $user->setPasswordHash($this->hasher->hash($password));

        $id = $this->users->save($user);
        $user->setId($id);

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