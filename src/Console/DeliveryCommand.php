<?php

declare(strict_types=1);

namespace Kater\SecurityObservability\Console;

use Illuminate\Console\Command;
use Kater\SecurityObservability\Delivery\Exporter;
use Kater\SecurityObservability\Delivery\Outbox;
use Kater\SecurityObservability\TelemetryState;
use Throwable;

final class DeliveryCommand extends Command
{
    protected $signature = 'security-observability:delivery {action=health : health, export, inspect, replay, or prune} {--id= : Event ID for inspect or replay}';

    protected $description = 'Inspect and operate durable telemetry without printing event payloads';

    public function handle(Outbox $outbox, Exporter $exporter, TelemetryState $state): int
    {
        try {
            switch ($this->argument('action')) {
                case 'health':
                    $health = $outbox->health() + ['process_failures' => $state->failures, 'process_rejected' => $state->rejected];
                    $this->line(json_encode($health, JSON_THROW_ON_ERROR));

                    return $health['capacity_exhausted'] || $health['quarantined'] > 0 ? self::FAILURE : self::SUCCESS;
                case 'export':
                    $this->info('Processed: '.$exporter->run());

                    return self::SUCCESS;
                case 'inspect':
                    $query = $outbox->rows()->select(['event_id', 'status', 'attempts', 'created_at', 'next_attempt', 'lease_until', 'failure', 'delivered_at']);
                    if ($this->option('id')) {
                        $query->where('event_id', $this->option('id'));
                    }
                    $this->line($query->orderBy('created_at')->limit(100)->get()->toJson());

                    return self::SUCCESS;
                case 'replay':
                    if (! $this->option('id') || ! $outbox->replay($this->option('id'))) {
                        $this->error('Specify the ID of a quarantined event.');

                        return self::FAILURE;
                    }
                    $this->info('Event queued for replay with its original ID.');

                    return self::SUCCESS;
                case 'prune':
                    $this->info('Pruned delivered records: '.$outbox->prune());

                    return self::SUCCESS;
                default:
                    $this->error('Unknown delivery action.');

                    return self::FAILURE;
            }
        } catch (Throwable) {
            $this->error('Delivery unavailable; check storage and exporter configuration.');

            return self::FAILURE;
        }
    }
}
