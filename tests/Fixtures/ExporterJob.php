<?php

declare(strict_types=1);

namespace Kater\SecurityObservability\Tests\Fixtures;

use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Support\Facades\Http;
use Kater\SecurityObservability\Contracts\EventRecorder;
use Kater\SecurityObservability\Events\OperationalEvent;
use Kater\SecurityObservability\Queue\ExcludeFromTelemetry;

final class ExporterJob implements ExcludeFromTelemetry, ShouldQueue
{
    public function handle(): void
    {
        app(EventRecorder::class)->record(new OperationalEvent('exporter.recursive'));
        Http::get('https://collector.test');
    }
}
