<?php

declare(strict_types=1);

namespace MonkeysLegion\Auth\Exception;

/**
 * Thrown when no policy is registered for a model.
 */
final class PolicyNotFoundException extends AuthException
{
    protected int $statusCode = 500;

    public function __construct(string $modelClass, array $context = [])
    {
        $context['model_class'] = $modelClass;
        parent::__construct("No policy registered for {$modelClass}", 7001, null, $context);
    }
}
