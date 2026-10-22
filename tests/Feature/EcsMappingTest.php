<?php

declare(strict_types=1);

namespace Kater\SecurityObservability\Tests\Feature;

use Illuminate\Support\Arr;
use Kater\SecurityObservability\Contracts\EventMapper;
use Kater\SecurityObservability\Contracts\EventRecorder;
use Kater\SecurityObservability\Contracts\EventSink;
use Kater\SecurityObservability\Events\Actor;
use Kater\SecurityObservability\Events\SanitizedEvent;
use Kater\SecurityObservability\Events\SecurityEvent;
use Kater\SecurityObservability\Events\Target;
use Kater\SecurityObservability\Export\Ecs\EcsMapper;
use Kater\SecurityObservability\Export\Ecs\MappingFailed;
use Kater\SecurityObservability\Export\Json\JsonEventSink;
use Kater\SecurityObservability\Tests\Fixtures\SocScenario;
use Kater\SecurityObservability\Tests\TelemetryTestCase;

final class EcsMappingTest extends TelemetryTestCase
{
    public function test_scenarios_match_pinned_ecs_field_types_and_categories(): void
    {
        SocScenario::emit($this->app);
        $schema = json_decode(file_get_contents(__DIR__.'/../Fixtures/ecs-9.5.0-fields.json'), true, flags: JSON_THROW_ON_ERROR);
        foreach ($this->sink->events as $native) {
            $ecs = (new EcsMapper)->map(new SanitizedEvent(json_encode($native, JSON_THROW_ON_ERROR)));
            self::assertSame($native['event_id'], $ecs['event']['id']);
            self::assertSame($native['occurred_at'], $ecs['@timestamp']);
            self::assertSame('event', $ecs['event']['kind']);
            self::assertSame('9.5.0', $ecs['ecs']['version']);
            self::assertStringNotContainsString('synthetic-secret', json_encode($ecs));
            foreach ($ecs['event']['category'] ?? [] as $category) {
                foreach ($ecs['event']['type'] as $type) {
                    self::assertContains($type, $schema['fields']['event.category']['expected_types'][$category]);
                }
            }
            unset($ecs['kater']);
            foreach (Arr::dot($ecs) as $key => $value) {
                $field = preg_replace('/\.\d+$/', '', $key);
                self::assertArrayHasKey($field, $schema['fields']);
                $definition = $schema['fields'][$field];
                match ($definition['type']) {
                    'keyword', 'date', 'ip' => self::assertIsString($value, $field),
                    'long' => self::assertIsInt($value, $field),
                };
                if (isset($definition['values'])) {
                    self::assertContains($value, $definition['values']);
                }
            }
        }
        $failed = (new EcsMapper)->map(new SanitizedEvent(json_encode($this->sink->events[0])));
        self::assertArrayNotHasKey('id', $failed['user']);
        self::assertSame('pseudo-user-1', $failed['user']['target']['id']);
        self::assertSame(['pseudo-user-1'], $failed['related']['user']);
        $http = array_values(array_filter($this->sink->events, fn ($e) => $e['name'] === 'http.request.completed'))[0];
        $mapped = (new EcsMapper)->map(new SanitizedEvent(json_encode($http)));
        self::assertSame(12125000, $mapped['event']['duration']);
        self::assertArrayNotHasKey('url', $mapped);
        self::assertSame('192.0.2.1', $mapped['source']['ip']);
        self::assertSame('workflow-synthetic', $mapped['kater']['correlation']['id']);
    }

    public function test_json_channel_maps_after_redaction_and_attributes_cannot_override_ecs(): void
    {
        $path = tempnam(sys_get_temp_dir(), 'ecs-');
        config(['security-observability.format' => 'ecs', 'logging.channels.security-observability.with.stream' => $path]);
        $this->app->forgetInstance(EventSink::class);
        $this->app->bind(EventSink::class, JsonEventSink::class);
        try {
            $this->app->make(EventRecorder::class)->record(new SecurityEvent('custom.observation', 'observe', attributes: ['event' => ['kind' => 'alert'], 'password' => 'synthetic-secret', 'network' => ['client_ip' => '[REDACTED]']]));
            $ecs = json_decode(file_get_contents($path), true, flags: JSON_THROW_ON_ERROR);
            self::assertSame('event', $ecs['event']['kind']);
            self::assertArrayNotHasKey('category', $ecs['event']);
            self::assertArrayNotHasKey('source', $ecs);
            self::assertSame('[REDACTED]', $ecs['kater']['attributes']['password']);
            self::assertInstanceOf(EcsMapper::class, $this->app->make(EventMapper::class));
        } finally {
            $this->app['log']->forgetChannel('security-observability');
            unlink($path);
        }
    }

    public function test_unknown_schema_is_rejected_instead_of_silently_mapped(): void
    {
        $this->expectException(MappingFailed::class);
        (new EcsMapper)->map(new SanitizedEvent('{"schema_version":"future"}'));
    }

    public function test_missing_identity_and_trace_are_not_invented_and_numeric_ids_are_keywords(): void
    {
        $recorder = $this->app->make(EventRecorder::class);
        $recorder->record(new SecurityEvent('identity.privilege.changed', 'change', actor: new Actor('user', 0), target: new Target('role', 'admin')));
        $ecs = (new EcsMapper)->map(new SanitizedEvent(json_encode($this->sink->events[0])));
        self::assertSame('0', $ecs['user']['id']);
        self::assertArrayNotHasKey('target', $ecs['user']);
        self::assertSame('admin', $ecs['kater']['target']['id']);
        self::assertArrayNotHasKey('trace', $ecs);
        self::assertArrayNotHasKey('span', $ecs);
        self::assertArrayNotHasKey('tenant', $ecs['kater']);
        self::assertArrayNotHasKey('organization', $ecs);
    }

    public function test_invalid_timestamps_are_rejected_and_milliseconds_are_not_confused_with_nanoseconds(): void
    {
        $this->app->make(EventRecorder::class)->record(new SecurityEvent('custom.test', 'observe'));
        $raw = $this->sink->events[0];
        $raw['occurred_at'] = '2026-02-30T12:00:00.000000Z';
        $this->expectException(MappingFailed::class);
        (new EcsMapper)->map(new SanitizedEvent(json_encode($raw)));
    }
}
