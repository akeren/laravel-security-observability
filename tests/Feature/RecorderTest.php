<?php

declare(strict_types=1);

namespace Kater\SecurityObservability\Tests\Feature;

use Kater\SecurityObservability\Context\CorrelationContext;
use Kater\SecurityObservability\Contracts\ContextResolver;
use Kater\SecurityObservability\Contracts\Event;
use Kater\SecurityObservability\Contracts\EventRecorder;
use Kater\SecurityObservability\Contracts\EventSink;
use Kater\SecurityObservability\Contracts\Redactor;
use Kater\SecurityObservability\Events\OperationalEvent;
use Kater\SecurityObservability\TelemetryState;
use Kater\SecurityObservability\Tests\TelemetryTestCase;
use RuntimeException;

final class RecorderTest extends TelemetryTestCase
{
    public function test_legacy_redaction_and_correlation_are_preserved_with_new_envelope(): void
    {
        $legacy = json_decode(file_get_contents(__DIR__.'/../Fixtures/legacy-operational.json'), true, flags: JSON_THROW_ON_ERROR);
        $this->app->make(CorrelationContext::class)->start($legacy['correlation_id'], $legacy['request_id']);
        $event = new OperationalEvent($legacy['event'], ['headers' => ['authorization' => 'synthetic-secret'], 'nested' => ['cardNumber' => 'synthetic-card'], 'visible' => 'yes', 'event_id' => 'spoof']);
        $this->app->make(EventRecorder::class)->record($event);
        $record = $this->sink->events[0];
        self::assertSame($event->id(), $record['event_id']);
        self::assertSame($legacy['event'], $record['name']);
        self::assertSame($legacy['correlation_id'], $record['correlation_id']);
        self::assertSame($legacy['context']['headers'], $record['attributes']['headers']);
        self::assertSame($legacy['context']['nested'], $record['attributes']['nested']);
        self::assertSame('yes', $record['attributes']['visible']);
        self::assertArrayNotHasKey('actor', $record);
        self::assertArrayNotHasKey('tenant', $record);
        self::assertArrayNotHasKey('trace_id', $record);
    }

    public function test_privacy_handles_cycles_objects_invalid_utf8_and_control_characters(): void
    {
        $cycle = [];
        $cycle['self'] = &$cycle;
        $object = new class implements \JsonSerializable
        {
            public function jsonSerialize(): mixed
            {
                throw new RuntimeException('must not execute');
            }
        };
        $attributes = ['cycle' => $cycle, 'object' => $object, 'number' => INF,
            'text' => "line\n\0\xff", 'nested' => ['api_key' => 'synthetic-secret']];
        $this->app->make(EventRecorder::class)->record(new OperationalEvent('test.privacy', $attributes));
        $record = $this->sink->events[0];
        $json = json_encode($record, JSON_THROW_ON_ERROR);
        self::assertStringNotContainsString('synthetic-secret', $json);
        self::assertStringContainsString('[DEPTH_LIMIT]', $json);
        self::assertSame('[UNSUPPORTED]', $record['attributes']['object']);
        self::assertSame('[UNSUPPORTED]', $record['attributes']['number']);
        self::assertStringNotContainsString("\n", $json);
        self::assertStringContainsString('\\ufffd', $json);
    }

    public function test_exact_paths_and_attribute_allowlist_apply_before_every_sink(): void
    {
        config(['security-observability.privacy.allowed_attribute_keys' => ['customer'],
            'security-observability.privacy.redact_paths' => ['/attributes/customer/email']]);
        $this->app->make(EventRecorder::class)->record(new OperationalEvent('test.fields', ['customer' => ['email' => 'synthetic@example.test'], 'other' => 'excluded']));
        self::assertSame(['customer' => ['email' => '[REDACTED]']], $this->sink->events[0]['attributes']);
    }

    public function test_limits_bound_collections_strings_and_total_event_bytes(): void
    {
        config(['security-observability.privacy.max_items' => 20, 'security-observability.privacy.max_string_bytes' => 128]);
        $recorder = $this->app->make(EventRecorder::class);
        $recorder->record(new OperationalEvent('test.limits', ['items' => array_fill(0, 100, str_repeat('x', 500))]));
        self::assertCount(20, $this->sink->events[0]['attributes']['items']);
        self::assertSame(128, strlen($this->sink->events[0]['attributes']['items'][0]));
        config(['security-observability.privacy.max_event_bytes' => 256]);
        $recorder->record(new OperationalEvent('test.oversize', ['large' => str_repeat('x', 500)]));
        self::assertCount(1, $this->sink->events);
        self::assertSame(1, $this->app->make(TelemetryState::class)->rejected);
    }

    public function test_failures_are_fail_open_and_recursion_is_suppressed(): void
    {
        $this->app->instance(EventSink::class, new class implements EventSink
        {
            public function write(Event $event): void
            {
                app(EventRecorder::class)->record(new OperationalEvent('recursive.event'));
                throw new RuntimeException('sink secret');
            }
        });
        $this->app->make(EventRecorder::class)->record(new OperationalEvent('test.failure'));
        self::assertSame(1, $this->app->make(TelemetryState::class)->failures);
        self::assertFalse($this->app->make(TelemetryState::class)->suppressed());
    }

    public function test_disabled_recorder_does_not_invoke_user_code(): void
    {
        config(['security-observability.enabled' => false]);
        $this->app->make(EventRecorder::class)->record(new class implements Event
        {
            public function id(): string
            {
                throw new RuntimeException;
            }

            public function toArray(): array
            {
                throw new RuntimeException;
            }
        });
        self::assertSame([], $this->sink->events);
        self::assertSame(0, $this->app->make(TelemetryState::class)->failures);
    }

    public function test_resolver_identity_is_redacted_and_attributes_cannot_override_it(): void
    {
        $this->app->bind(ContextResolver::class, fn () => new class implements ContextResolver
        {
            public function resolve(): array
            {
                return ['tenant' => ['id' => 'tenant-a'], 'actor' => ['id' => 'user-a', 'token' => 'secret']];
            }
        });
        $this->app->make(EventRecorder::class)->record(new OperationalEvent('test.identity', ['tenant' => ['id' => 'tenant-b']]));
        self::assertSame('tenant-a', $this->sink->events[0]['tenant']['id']);
        self::assertSame('[REDACTED]', $this->sink->events[0]['actor']['token']);
        $this->app->bind(ContextResolver::class, fn () => new class implements ContextResolver
        {
            public function resolve(): array
            {
                return ['tenant' => ['id' => 'tenant-b']];
            }
        });
        $this->app->make(EventRecorder::class)->record(new OperationalEvent('test.next'));
        self::assertSame('tenant-b', $this->sink->events[1]['tenant']['id']);
        self::assertArrayNotHasKey('actor', $this->sink->events[1]);
    }

    public function test_redactor_failure_is_counted_and_does_not_reach_sink(): void
    {
        $this->app->bind(Redactor::class, fn () => new class implements Redactor
        {
            public function redact(array $data): array
            {
                throw new RuntimeException('normalizer failed');
            }
        });
        $this->app->make(EventRecorder::class)->record(new OperationalEvent('test.redaction'));
        self::assertSame([], $this->sink->events);
        self::assertSame(1, $this->app->make(TelemetryState::class)->failures);
    }

    public function test_tight_limits_preserve_envelope_and_do_not_bypass_sensitive_key_matching(): void
    {
        config(['security-observability.privacy.max_items' => 2, 'security-observability.privacy.max_string_bytes' => 16]);
        $event = new OperationalEvent('test.tight', [str_repeat('a', 40).'token' => 'secret-value', 'text' => str_repeat("\xff", 50), 'third' => 'omitted']);
        $this->app->make(EventRecorder::class)->record($event);
        $record = $this->sink->events[0];
        self::assertSame($event->id(), $record['event_id']);
        self::assertCount(2, $record['attributes']);
        self::assertSame('[REDACTED]', $record['attributes'][str_repeat('a', 40).'token']);
        self::assertLessThanOrEqual(16, strlen($record['attributes']['text']));
    }

    public function test_serialization_failure_does_not_reach_any_sink(): void
    {
        $this->app->make(EventRecorder::class)->record(new class implements Event
        {
            public function id(): string
            {
                return 'synthetic-event';
            }

            public function toArray(): array
            {
                throw new RuntimeException('synthetic serialization secret');
            }
        });
        self::assertSame([], $this->sink->events);
        self::assertSame(1, $this->app->make(TelemetryState::class)->failures);
    }
}
