<?php

declare(strict_types=1);

namespace Kater\SecurityObservability\Context;

use Kater\SecurityObservability\Contracts\ContextResolver;

final class NullContextResolver implements ContextResolver
{
    public function resolve(): array
    {
        return [];
    }
}
