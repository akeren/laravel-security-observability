<?php

declare(strict_types=1);

namespace Kater\SecurityObservability\Contracts;

use Kater\SecurityObservability\Events\SanitizedEvent;
use Kater\SecurityObservability\Export\MappingFailed;

interface EventMapper
{
    /**
     * Map only the sanitized envelope; retain the original event identity and timestamps.
     *
     * @return array<string, mixed> JSON-safe document for the selected output schema.
     *
     * @throws MappingFailed When the event cannot be mapped; delivery quarantines it.
     */
    public function map(SanitizedEvent $event): array;
}
