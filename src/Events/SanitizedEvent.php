<?php

declare(strict_types=1);

namespace Kater\SecurityObservability\Events;

use Kater\SecurityObservability\Contracts\Event;

/** Frozen scalar JSON; no references to caller-owned objects or arrays. */
final readonly class SanitizedEvent implements Event
{
    public function __construct(private string $json) {}

    public function id(): string
    {
        return $this->toArray()['event_id'];
    }

    public function toArray(): array
    {
        return json_decode($this->json, true, flags: JSON_THROW_ON_ERROR);
    }
}
