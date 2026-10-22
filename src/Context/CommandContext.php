<?php

declare(strict_types=1);

namespace Kater\SecurityObservability\Context;

use Illuminate\Container\Container;
use Illuminate\Contracts\Config\Repository;

final class CommandContext
{
    private array $stack = [];

    public function __construct(private Container $app, private Repository $config) {}

    public function starting(): void
    {
        $context = $this->app->make(CorrelationContext::class);
        $this->stack[] = [$context, $context->snapshot()];
        $context->clear();
        if ($this->config->get('security-observability.enabled')) {
            $context->start();
        }
    }

    public function finished(): void
    {
        $frame = array_pop($this->stack);
        if ($frame !== null) {
            [$context, $snapshot] = $frame;
            $context->restore($snapshot);
        }
    }
}
