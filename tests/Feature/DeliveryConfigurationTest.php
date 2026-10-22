<?php

declare(strict_types=1);

namespace Kater\SecurityObservability\Tests\Feature;

use Kater\SecurityObservability\Contracts\DeliveryStore;
use Kater\SecurityObservability\Contracts\DeliveryTransport;
use Kater\SecurityObservability\Contracts\EventRecorder;
use Kater\SecurityObservability\Contracts\EventSink;
use Kater\SecurityObservability\Delivery\DeliveryResult;
use Kater\SecurityObservability\Delivery\Exporter;
use Kater\SecurityObservability\Events\SanitizedEvent;
use Kater\SecurityObservability\Events\SecurityEvent;
use Kater\SecurityObservability\Export\Json\JsonEventSink;
use Kater\SecurityObservability\SecurityObservabilityServiceProvider;
use Kater\SecurityObservability\Tests\TestCase;
use LogicException;
use PHPUnit\Framework\Attributes\DataProvider;

final class DeliveryConfigurationTest extends TestCase
{
    public static function invalidDrivers(): iterable
    {
        foreach (['outbx', '', null, false, 1, [], 'OUTBOX'] as $value) {
            yield [$value];
        }
    }

    #[DataProvider('invalidDrivers')]
    public function test_invalid_driver_is_rejected_at_registration(mixed $driver): void
    {
        config(['security-observability.delivery.driver' => $driver]);
        $this->expectException(LogicException::class);
        (new SecurityObservabilityServiceProvider($this->app))->register();
    }

    public function test_invalid_driver_cannot_silently_select_json(): void
    {
        config(['security-observability.delivery.driver' => 'outbx']);
        $this->expectException(LogicException::class);
        app(EventSink::class);
    }

    public function test_custom_sink_cannot_bypass_invalid_strict_configuration(): void
    {
        config(['security-observability.enabled' => true,
            'security-observability.delivery.driver' => 'outbx',
            'security-observability.delivery.strict_security' => true]);
        $sink = $this->createMock(EventSink::class);
        $sink->expects(self::never())->method('write');
        $this->app->instance(EventSink::class, $sink);
        $this->expectException(LogicException::class);
        app(EventRecorder::class)->record(new SecurityEvent('security.test', 'observe'));
    }

    public function test_exporter_accepts_custom_store_and_transport_without_concrete_dependencies(): void
    {
        config(['security-observability.enabled' => true, 'security-observability.delivery.driver' => 'outbox']);
        $row = (object) ['event_id' => 'synthetic-id', 'payload' => '{"event_id":"synthetic-id"}', 'attempts' => 1, 'lease_token' => 'synthetic-lease'];
        $store = $this->createMock(DeliveryStore::class);
        $store->expects(self::exactly(2))->method('claim')->willReturnOnConsecutiveCalls($row, null);
        $store->expects(self::once())->method('finish')->with($row, 'delivered', null, 0);
        $transport = $this->createMock(DeliveryTransport::class);
        $transport->expects(self::once())->method('validate');
        $transport->expects(self::once())->method('send')->with(self::callback(fn (SanitizedEvent $event) => $event->id() === 'synthetic-id'))->willReturn(DeliveryResult::delivered());
        $this->app->instance(DeliveryStore::class, $store);
        $this->app->instance(DeliveryTransport::class, $transport);
        self::assertSame(1, app(Exporter::class)->run());
    }

    public function test_sink_type_rejects_unsanitized_events_before_writing(): void
    {
        $sink = app(JsonEventSink::class);
        $this->expectException(\TypeError::class);
        $sink->write(new SecurityEvent('security.test', 'observe', attributes: ['password' => 'synthetic-secret']));
    }

    public function test_transport_validation_happens_before_leasing(): void
    {
        config(['security-observability.enabled' => true, 'security-observability.delivery.driver' => 'outbox']);
        $store = $this->createMock(DeliveryStore::class);
        $store->expects(self::never())->method('claim');
        $transport = $this->createMock(DeliveryTransport::class);
        $transport->method('validate')->willThrowException(new LogicException('Invalid transport'));
        $transport->expects(self::never())->method('send');
        $this->app->instance(DeliveryStore::class, $store);
        $this->app->instance(DeliveryTransport::class, $transport);
        $this->expectException(LogicException::class);
        app(Exporter::class)->run();
    }
}
