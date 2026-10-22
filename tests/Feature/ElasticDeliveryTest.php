<?php

declare(strict_types=1);

namespace Kater\SecurityObservability\Tests\Feature;

use Illuminate\Http\Client\Factory;
use Kater\SecurityObservability\Contracts\EcsEventMapper;
use Kater\SecurityObservability\Contracts\EventMapper;
use Kater\SecurityObservability\Contracts\EventRecorder;
use Kater\SecurityObservability\Delivery\Exporter;
use Kater\SecurityObservability\Delivery\Outbox;
use Kater\SecurityObservability\Events\SanitizedEvent;
use Kater\SecurityObservability\Events\SecurityEvent;
use Kater\SecurityObservability\Export\Ecs\EcsMapper;
use Kater\SecurityObservability\Tests\TestCase;

final class ElasticDeliveryTest extends TestCase
{
    protected function defineEnvironment($app): void
    {
        $app['config']->set('database.default', 'testing');
        $app['config']->set('database.connections.testing', ['driver' => 'sqlite', 'database' => ':memory:', 'prefix' => '']);
        foreach (['enabled' => true, 'format' => 'ecs', 'delivery.driver' => 'outbox', 'delivery.transport' => 'elasticsearch',
            'delivery.endpoint' => 'https://elastic.example/security-observability/_doc', 'delivery.auth_scheme' => 'ApiKey', 'delivery.token' => 'synthetic-key'] as $key => $value) {
            $app['config']->set('security-observability.'.$key, $value);
        }
    }

    protected function setUp(): void
    {
        parent::setUp();
        (require __DIR__.'/../../database/migrations/2026_10_18_000000_create_security_observability_outbox.php')->up();
        $this->app->make(EventRecorder::class)->record(new SecurityEvent('security.test', 'observe', attributes: ['token' => 'synthetic-secret']));
    }

    public function test_delivery_requires_document_acknowledgment_and_keeps_native_outbox_payload(): void
    {
        $outbox = $this->app->make(Outbox::class);
        $row = $outbox->rows()->first();
        $http = $this->app->make(Factory::class);
        $http->fakeSequence()->push(['errors' => false], 200)
            ->push(['_id' => $row->event_id, 'result' => 'created', '_shards' => ['failed' => 0]], 201);
        $this->app->make(Exporter::class)->run();
        self::assertSame('pending', $outbox->rows()->first()->status);
        self::assertSame('invalid_acknowledgment', $outbox->rows()->first()->failure);
        $outbox->rows()->update(['next_attempt' => time() - 1]);
        $this->app->make(Exporter::class)->run();
        self::assertSame('delivered', $outbox->rows()->first()->status);
        self::assertSame($row->payload, $outbox->rows()->first()->payload);
        foreach ($http->recorded() as [$request]) {
            self::assertSame('PUT', $request->method());
            self::assertStringEndsWith('/_doc/'.$row->event_id, $request->url());
            self::assertSame(['ApiKey synthetic-key'], $request->header('Authorization'));
            self::assertSame($row->event_id, $request['event']['id']);
            self::assertStringNotContainsString('synthetic-secret', $request->body());
        }
    }

    public function test_unmappable_events_are_quarantined_without_network_requests(): void
    {
        $outbox = $this->app->make(Outbox::class);
        $outbox->rows()->update(['payload' => '{"schema_version":"future"}']);
        $http = $this->app->make(Factory::class);
        $http->fake();
        $this->app->make(Exporter::class)->run();
        self::assertSame('quarantined', $outbox->rows()->first()->status);
        self::assertSame('mapping', $outbox->rows()->first()->failure);
        $http->assertNothingSent();
    }

    public function test_partial_shard_failure_does_not_acknowledge_delivery(): void
    {
        $outbox = $this->app->make(Outbox::class);
        $row = $outbox->rows()->first();
        $http = $this->app->make(Factory::class);
        $http->fake(['*' => $http->response(['_id' => $row->event_id, 'result' => 'created', '_shards' => ['failed' => 1]], 201)]);
        $this->app->make(Exporter::class)->run();
        self::assertSame('pending', $outbox->rows()->first()->status);
        self::assertSame('invalid_acknowledgment', $outbox->rows()->first()->failure);
    }

    public function test_custom_ecs_mapper_capability_is_accepted(): void
    {
        $this->app->instance(EventMapper::class, new class implements EcsEventMapper
        {
            public function map(SanitizedEvent $event): array
            {
                return (new EcsMapper)->map($event);
            }
        });
        $row = app(Outbox::class)->rows()->first();
        app(Factory::class)->fake(['*' => app(Factory::class)->response(['_id' => $row->event_id, 'result' => 'created', '_shards' => ['failed' => 0]], 201)]);
        self::assertSame(1, app(Exporter::class)->run());
        self::assertSame('delivered', app(Outbox::class)->rows()->first()->status);
    }

    public function test_elastic_transport_requires_ecs_before_claiming_events(): void
    {
        config(['security-observability.format' => 'native']);
        $this->artisan('security-observability:delivery export')->assertFailed();
        self::assertSame(0, $this->app->make(Outbox::class)->rows()->first()->attempts);
    }
}
