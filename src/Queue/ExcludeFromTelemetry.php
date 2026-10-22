<?php

declare(strict_types=1);

namespace Kater\SecurityObservability\Queue;

/** Exporter jobs must implement this marker to prevent recursive telemetry. */
interface ExcludeFromTelemetry {}
