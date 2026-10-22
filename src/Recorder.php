<?php

declare(strict_types=1);

namespace Kater\SecurityObservability;

use DateTimeImmutable;
use DateTimeZone;
use Illuminate\Contracts\Config\Repository;
use Kater\SecurityObservability\Context\CorrelationContext;
use Kater\SecurityObservability\Contracts\ContextResolver;
use Kater\SecurityObservability\Contracts\Event;
use Kater\SecurityObservability\Contracts\EventRecorder;
use Kater\SecurityObservability\Contracts\EventSink;
use Kater\SecurityObservability\Contracts\Redactor;
use Kater\SecurityObservability\Delivery\DeliveryDriver;
use Kater\SecurityObservability\Delivery\PersistenceFailed;
use Kater\SecurityObservability\Events\ContextualEvent;
use Kater\SecurityObservability\Events\SanitizedEvent;
use Kater\SecurityObservability\Events\SecurityEvent;
use Throwable;

final class Recorder implements EventRecorder
{
    public function __construct(private Repository $config, private CorrelationContext $context,
        private ContextResolver $resolver, private Redactor $redactor, private EventSink $sink, private TelemetryState $state) {}

    public function record(Event $event): void
    {
        if (! $this->config->get('security-observability.enabled') || $this->state->suppressed()) {
            return;
        }
        $driver = DeliveryDriver::configured($this->config);
        $strict = $driver === DeliveryDriver::Outbox
            && $this->config->get('security-observability.delivery.strict_security')
            && ($event instanceof SecurityEvent);
        $this->state->enter();
        try {
            $raw = $event->toArray();
            $strict = $strict || (($raw['kind'] ?? null) === 'security' && $this->config->get('security-observability.delivery.driver') === 'outbox' && $this->config->get('security-observability.delivery.strict_security'));
            if (($raw['kind'] ?? null) === 'security' && ! $this->config->get('security-observability.security.enabled')) {
                return;
            }
            $payload = [
                'schema_version' => '0.2', 'event_id' => $event->id(),
                'occurred_at' => $raw['occurred_at'] ?? null,
                'observed_at' => (new DateTimeImmutable('now', new DateTimeZone('UTC')))->format('Y-m-d\TH:i:s.u\Z'),
                'kind' => $raw['kind'] ?? 'operational', 'name' => $raw['name'] ?? 'unknown',
                'action' => $raw['action'] ?? 'unknown', 'outcome' => $raw['outcome'] ?? 'unknown',
                'severity' => $raw['severity'] ?? 'informational',
                'service' => $this->config->get('security-observability.service'),
                'environment' => $this->config->get('security-observability.environment'),
                ...$this->context->snapshot(),
            ];
            $resolved = $event instanceof ContextualEvent ? $event->context : $this->resolver->resolve();
            $identityKeys = array_flip(['actor', 'tenant', 'target']);
            $payload += array_filter(array_intersect_key($raw, $identityKeys), static fn ($value) => $value !== null);
            $payload += array_intersect_key($resolved, $identityKeys);
            $payload['attributes'] = $raw['attributes'] ?? [];
            $identity = array_intersect_key($payload, array_flip(['schema_version', 'event_id', 'occurred_at', 'observed_at', 'kind', 'name', 'action', 'outcome', 'severity', 'correlation_id', 'request_id', 'trace_id', 'span_id']));
            $payload = $this->redactor->redact($payload);
            if (array_intersect_key($payload, $identity) !== $identity) {
                $this->state->rejected++;
                if ($strict) {
                    throw new PersistenceFailed('Security event rejected.');
                }

                return;
            }
            $json = json_encode($payload, JSON_THROW_ON_ERROR | JSON_INVALID_UTF8_SUBSTITUTE | JSON_UNESCAPED_SLASHES | JSON_PRESERVE_ZERO_FRACTION);
            if (strlen($json) > max(256, (int) $this->config->get('security-observability.privacy.max_event_bytes', 32768))) {
                $this->state->rejected++;
                if ($strict) {
                    throw new PersistenceFailed('Security event rejected.');
                }

                return;
            }
            $this->sink->write(new SanitizedEvent($json));
        } catch (Throwable) {
            $this->state->failures++;
            if ($strict) {
                throw new PersistenceFailed('Security event could not be persisted.');
            }
        } finally {
            $this->state->leave();
        }
    }
}
