<?php

declare(strict_types=1);

namespace Kater\SecurityObservability\Delivery;

use Illuminate\Bus\Queueable;
use Illuminate\Contracts\Queue\ShouldQueue;
use Kater\SecurityObservability\Queue\ExcludeFromTelemetry;

final class ExportOutbox implements ExcludeFromTelemetry, ShouldQueue
{
    use Queueable;

    public function __construct()
    {
        $this->afterCommit();
    }

    public function handle(Exporter $exporter): void
    {
        $exporter->run();
    }
}
