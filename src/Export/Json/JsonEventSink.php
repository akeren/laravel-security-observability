<?php

declare(strict_types=1);

namespace Kater\SecurityObservability\Export\Json;

use Illuminate\Contracts\Config\Repository;
use Illuminate\Log\LogManager;
use Kater\SecurityObservability\Contracts\EventMapper;
use Kater\SecurityObservability\Contracts\EventSink;
use Kater\SecurityObservability\Events\SanitizedEvent;
use Kater\SecurityObservability\Events\Severity;

final class JsonEventSink implements EventSink
{
    public function __construct(private LogManager $logs, private Repository $config, private EventMapper $mapper) {}

    public function write(SanitizedEvent $event): void
    {
        $payload = $event->toArray();
        $level = Severity::tryFrom($payload['severity'] ?? '')?->logLevel() ?? 'info';
        $this->logs->channel($this->config->get('security-observability.channel'))->log($level, $payload['name'], ['event' => $this->mapper->map($event)]);
    }
}
