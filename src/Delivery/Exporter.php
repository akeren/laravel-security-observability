<?php

declare(strict_types=1);

namespace Kater\SecurityObservability\Delivery;

use Illuminate\Contracts\Config\Repository;
use Kater\SecurityObservability\Contracts\DeliveryStore;
use Kater\SecurityObservability\Contracts\DeliveryTransport;
use Kater\SecurityObservability\Contracts\RetryPolicy;
use Kater\SecurityObservability\Events\SanitizedEvent;
use Kater\SecurityObservability\TelemetryState;
use RuntimeException;
use Throwable;

/** Orchestrates leased delivery; transport and retry policy are independently replaceable. */
final class Exporter
{
    public function __construct(private DeliveryStore $outbox, private DeliveryTransport $transport,
        private Repository $config, private TelemetryState $state, private RetryPolicy $retry) {}

    /** Return the number of claimed events processed, not the number delivered successfully. */
    public function run(): int
    {
        if (! $this->config->get('security-observability.enabled') || DeliveryDriver::configured($this->config) !== DeliveryDriver::Outbox) {
            return 0;
        }
        $this->transport->validate();
        $this->state->enter();
        $processed = 0;
        try {
            $batch = max(1, min(1000, (int) $this->config->get('security-observability.delivery.batch_size', 100)));
            for ($i = 0; $i < $batch; $i++) {
                $row = $this->outbox->claim();
                if (! $row) {
                    break;
                }
                $processed++;
                if ($row->attempts > $this->retry->attempts()) {
                    $this->outbox->finish($row, 'quarantined', 'attempt_limit');

                    continue;
                }
                $result = $this->transport->send(new SanitizedEvent($row->payload));
                if ($result->status === 'pending' && $row->attempts >= $this->retry->attempts()) {
                    $this->outbox->finish($row, 'quarantined', $result->failure);
                } else {
                    $this->outbox->finish($row, $result->status, $result->failure,
                        $result->status === 'pending' ? $this->retry->delay($row->attempts, $result->retryAfter) : 0);
                }
            }

            return $processed;
        } catch (Throwable) {
            throw new RuntimeException('Telemetry export failed; pending leases remain recoverable.');
        } finally {
            $this->state->leave();
        }
    }
}
