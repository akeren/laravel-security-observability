<?php

declare(strict_types=1);

namespace Kater\SecurityObservability\Events;

use Kater\SecurityObservability\Contracts\Event;

/** @internal Captures identity before an asynchronous operation can leave its originating scope. */
final readonly class ContextualEvent implements Event
{
    public function __construct(private Event $event, public array $context) {}

    public function id(): string
    {
        return $this->event->id();
    }

    public function toArray(): array
    {
        return $this->event->toArray();
    }
}
