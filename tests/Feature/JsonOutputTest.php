<?php

declare(strict_types=1);

namespace Kater\SecurityObservability\Tests\Feature;

use Kater\SecurityObservability\Contracts\EventRecorder;
use Kater\SecurityObservability\Contracts\EventSink;
use Kater\SecurityObservability\Events\OperationalEvent;
use Kater\SecurityObservability\Export\Json\JsonEventSink;
use Kater\SecurityObservability\Tests\TelemetryTestCase;

final class JsonOutputTest extends TelemetryTestCase
{
    public function test_actual_channel_writes_one_json_object_per_line_without_nested_json(): void
    {
        $path = tempnam(sys_get_temp_dir(), 'telemetry-json-');
        config(['logging.channels.security-observability.with.stream' => $path]);
        $this->app->bind(EventSink::class, JsonEventSink::class);
        try {
            $recorder = $this->app->make(EventRecorder::class);
            $recorder->record(new OperationalEvent('test.json', ['value' => "line1\nline2", 'token' => 'synthetic-secret']));
            $recorder->record(new OperationalEvent('test.next'));
            $lines = file($path, FILE_IGNORE_NEW_LINES);
            self::assertCount(2, $lines);
            $data = json_decode($lines[0], true, flags: JSON_THROW_ON_ERROR);
            self::assertSame('test.json', $data['name']);
            self::assertIsArray($data['attributes']);
            self::assertSame('[REDACTED]', $data['attributes']['token']);
            self::assertArrayNotHasKey('message', $data);
        } finally {
            $this->app['log']->forgetChannel('security-observability');
            unlink($path);
        }
    }
}
