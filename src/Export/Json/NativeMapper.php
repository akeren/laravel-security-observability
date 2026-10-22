<?php

declare(strict_types=1);

namespace Kater\SecurityObservability\Export\Json;

use Kater\SecurityObservability\Contracts\EventMapper;
use Kater\SecurityObservability\Events\SanitizedEvent;

final class NativeMapper implements EventMapper
{
    public function map(SanitizedEvent $event): array
    {
        return $event->toArray();
    }
}
