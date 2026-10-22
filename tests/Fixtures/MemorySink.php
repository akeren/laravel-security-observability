<?php

declare(strict_types=1);

namespace Kater\SecurityObservability\Tests\Fixtures;

use Kater\SecurityObservability\Contracts\Event;
use Kater\SecurityObservability\Contracts\EventSink;

final class MemorySink implements EventSink
{
    public array $events = [];

    public function write(Event $event): void
    {
        $this->events[] = $event->toArray();
    }
}
