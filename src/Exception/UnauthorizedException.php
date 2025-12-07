<?php

declare(strict_types=1);

namespace MonkeysLegion\Auth\Exception;

/**
 * Thrown when user lacks authorization for an action.
 */
final class UnauthorizedException extends AuthException
{
    public function __construct(
        string $ability = '',
        ?string $model = null,
        string $message = 'Unauthorized',
        array $context = []
    ) {
        if ($ability !== '') {
            $context['ability'] = $ability;
        }
        if ($model !== null) {
            $context['model'] = $model;
        }
        
        parent::__construct($message, 403, null, $context);
    }
}
