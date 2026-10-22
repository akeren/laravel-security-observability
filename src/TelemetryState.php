<?php

declare(strict_types=1);

namespace Kater\SecurityObservability;

/** Process-local diagnostics, deliberately never reported through the failing sink. */
final class TelemetryState
{
    public int $rejected = 0;

    public int $failures = 0;

    private int $suppression = 0;

    public function suppressed(): bool
    {
        return $this->suppression > 0;
    }

    public function enter(): void
    {
        $this->suppression++;
    }

    public function leave(): void
    {
        $this->suppression = max(0, $this->suppression - 1);
    }
}
