<?php

declare(strict_types=1);

namespace MonkeysLegion\Auth;

use MonkeysLegion\Repository\UserRepository;
use MonkeysLegion\Entity\User;
use RuntimeException;

final class AuthService
{
    public function __construct(
        private UserRepository $users,
        private PasswordHasher $hasher,
        private JwtService     $jwt
    ) {}

    public function register(string $email, string $password): User
    {
        if ($this->users->findBy(['email' => $email])) {
            throw new RuntimeException('Email already registered');
        }

        $user = new User();
        $user->setEmail($email);
        $user->setPasswordHash($this->hasher->hash($password));

        $id = $this->users->save($user);
        $user->setId($id);

        return $user;
    }

    public function login(string $email, string $password): string
    {
        $user = $this->users->findBy(['email' => $email]);
        if (!$user || !$this->hasher->verify($password, $user->getPasswordHash())) {
            throw new RuntimeException('Invalid credentials');
        }

        return $this->jwt->issue(['sub' => $user->getId()]);
    }
}