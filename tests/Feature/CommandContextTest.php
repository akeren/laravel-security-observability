<?php

declare(strict_types=1);

namespace Kater\SecurityObservability\Tests\Feature;

use Illuminate\Contracts\Console\Kernel;
use Illuminate\Support\Facades\Artisan;
use Kater\SecurityObservability\Context\CorrelationContext;
use Kater\SecurityObservability\Tests\TelemetryTestCase;

final class CommandContextTest extends TelemetryTestCase
{
    public function test_commands_isolate_context_and_restore_an_enclosing_request(): void
    {
        // Laravel deliberately disables Symfony command event forwarding during unit tests.
        $kernel = $this->app->make(Kernel::class);
        $kernel->rerouteSymfonyCommandEvents();
        $kernel->setArtisan(null);
        $seen = [];
        Artisan::command('telemetry:context', function () use (&$seen): void {
            $seen[] = app(CorrelationContext::class)->snapshot();
        });
        $context = $this->app->make(CorrelationContext::class);
        $context->start('request-workflow', 'request');
        Artisan::call('telemetry:context');
        self::assertSame('request-workflow', $context->snapshot()['correlation_id']);
        $context->clear();
        Artisan::call('telemetry:context');
        self::assertSame([], $context->snapshot());
        self::assertNotSame($seen[0]['correlation_id'], $seen[1]['correlation_id']);
        self::assertNotSame('request-workflow', $seen[0]['correlation_id']);
    }
}
