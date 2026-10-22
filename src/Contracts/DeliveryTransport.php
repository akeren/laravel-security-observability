<?php

declare(strict_types=1);

namespace Kater\SecurityObservability\Contracts;

use Kater\SecurityObservability\Delivery\DeliveryResult;
use Kater\SecurityObservability\Events\SanitizedEvent;

interface DeliveryTransport
{
    /** Validate configuration before any events are leased or network requests made. */
    public function validate(): void;

    /** Send one sanitized event, preserving its ID; never include sensitive text in the result. */
    public function send(SanitizedEvent $event): DeliveryResult;
}
