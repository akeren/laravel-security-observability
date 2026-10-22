<?php

declare(strict_types=1);

namespace Kater\SecurityObservability\Contracts;

/** Shared boundary for operational and typed security events. */
interface Event
{
    /** Return the same unique identifier for the lifetime of this event. */
    public function id(): string;

    /** @return array<string, mixed> */
    public function toArray(): array;
}
