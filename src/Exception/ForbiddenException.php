<?php

declare(strict_types=1);

namespace MonkeysLegion\Auth\Exception;

/**
 * Thrown when a user lacks permission for an action.
 */
final class ForbiddenException extends AuthException
{
    protected int $statusCode = 403;

    public function __construct(
        string $message = 'Access denied',
        ?string $ability = null,
        ?string $resource = null,
        array $context = []
    ) {
        $context['ability'] = $ability;
        $context['resource'] = $resource;
        parent::__construct($message, 403, null, $context);
    }
}
