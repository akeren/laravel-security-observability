<?php

declare(strict_types=1);

namespace Kater\SecurityObservability\Delivery;

use Illuminate\Contracts\Config\Repository;
use LogicException;

/** Reject invalid configuration instead of silently weakening persistence guarantees. */
enum DeliveryDriver: string
{
    case Json = 'json';
    case Outbox = 'outbox';

    public static function configured(Repository $config): self
    {
        return match ($config->get('security-observability.delivery.driver', 'json')) {
            'json' => self::Json,
            'outbox' => self::Outbox,
            default => throw new LogicException('Unsupported telemetry delivery driver.'),
        };
    }
}
