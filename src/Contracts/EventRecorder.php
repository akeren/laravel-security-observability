<?php

declare(strict_types=1);

namespace Kater\SecurityObservability\Contracts;

use Kater\SecurityObservability\Delivery\PersistenceFailed;

/** Enriches and sanitizes events before handing them to the configured sink. */
interface EventRecorder
{
    /**
     * Operational capture is fail-open; strict outbox security capture propagates failure.
     *
     * @throws PersistenceFailed When strict security persistence fails.
     */
    public function record(Event $event): void;
}
