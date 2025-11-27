<?php

declare(strict_types=1);

namespace MonkeysLegion\Auth\Exception;

/**
 * Thrown when 2FA verification is required but not provided.
 */
final class TwoFactorRequiredException extends AuthException
{
    private string $challengeToken;

    public function __construct(
        string $challengeToken,
        string $message = 'Two-factor authentication required',
        array $context = []
    ) {
        $this->challengeToken = $challengeToken;
        $context['challenge_token'] = $challengeToken;

        parent::__construct($message, 428, null, $context);
    }

    public function getChallengeToken(): string
    {
        return $this->challengeToken;
    }
}
