<?php

declare(strict_types=1);

namespace Kater\SecurityObservability\Tests;

use Kater\SecurityObservability\Contracts\EventSink;
use Kater\SecurityObservability\Tests\Fixtures\MemorySink;

abstract class TelemetryTestCase extends TestCase
{
    protected MemorySink $sink;

    protected function defineEnvironment($app): void
    {
        $app['config']->set('security-observability.enabled', true);
        $app['config']->set('queue.default', 'sync');
    }

    protected function setUp(): void
    {
        parent::setUp();
        $this->sink = new MemorySink;
        $this->app->instance(EventSink::class, $this->sink);
    }
}
