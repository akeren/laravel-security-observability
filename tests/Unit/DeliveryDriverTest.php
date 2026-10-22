<?php

declare(strict_types=1);

namespace Kater\SecurityObservability\Tests\Unit;

use Illuminate\Config\Repository;
use Kater\SecurityObservability\Delivery\DeliveryDriver;
use LogicException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class DeliveryDriverTest extends TestCase
{
    public function test_default_driver_is_json_and_explicit_outbox_is_preserved(): void
    {
        $config = new Repository;
        self::assertSame(DeliveryDriver::Json, DeliveryDriver::configured($config));
        $config->set('security-observability.delivery.driver', 'json');
        self::assertSame(DeliveryDriver::Json, DeliveryDriver::configured($config));
        $config->set('security-observability.delivery.driver', 'outbox');
        self::assertSame(DeliveryDriver::Outbox, DeliveryDriver::configured($config));
    }

    public static function invalidDrivers(): iterable
    {
        foreach (['outbx', '', 'JSON', 'OUTBOX', null, true, false, 0, 1, []] as $driver) {
            yield [$driver];
        }
    }

    #[DataProvider('invalidDrivers')]
    public function test_unsupported_driver_values_never_fall_back_to_json(mixed $driver): void
    {
        $this->expectException(LogicException::class);
        DeliveryDriver::configured(new Repository(['security-observability' => ['delivery' => ['driver' => $driver]]]));
    }
}
