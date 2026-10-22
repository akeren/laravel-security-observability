<?php

declare(strict_types=1);

namespace Kater\SecurityObservability\Contracts;

use Kater\SecurityObservability\Events\SanitizedEvent;

/** Writes the sanitized envelope; implementations must not reintroduce unsanitized context. */
interface EventSink
{
    /**
     * Receives a SanitizedEvent from the recorder. Preserve its event ID across retries.
     * Throw on write failure so the recorder can apply its configured failure policy.
     */
    public function write(SanitizedEvent $event): void;
}
