<?php

declare(strict_types=1);

namespace Kater\SecurityObservability\Delivery;

use Illuminate\Contracts\Config\Repository;
use Illuminate\Database\Connection;
use Illuminate\Database\DatabaseManager;
use Illuminate\Database\Query\Builder;
use Illuminate\Support\Str;
use Kater\SecurityObservability\Contracts\DeliveryStore;
use Kater\SecurityObservability\Contracts\EventSink;
use Kater\SecurityObservability\Events\SanitizedEvent;
use LogicException;

/** Database sink with bounded capacity, leased delivery, and event-ID deduplication. */
final class Outbox implements DeliveryStore, EventSink
{
    public function __construct(private DatabaseManager $database, private Repository $config) {}

    private function connection(): Connection
    {
        return $this->database->connection($this->config->get('security-observability.delivery.connection'));
    }

    public function rows(): Builder
    {
        return $this->connection()->table('security_observability_outbox');
    }

    private function locked(callable $callback): mixed
    {
        return $this->connection()->transaction(function () use ($callback) {
            // A real write also serializes SQLite writers; row locks serialize other engines.
            if ($this->connection()->table('security_observability_state')->where('id', 1)->update(['lock_marker' => $this->connection()->raw('1 - lock_marker')]) !== 1) {
                throw new LogicException('Outbox state is not initialized.');
            }

            return $callback();
        });
    }

    /**
     * Persist a SanitizedEvent on the configured connection, joining any existing transaction.
     *
     * @throws LogicException When called with an unsanitized event or uninitialized storage.
     * @throws PersistenceFailed When capacity is exhausted.
     */
    public function write(SanitizedEvent $event): void
    {
        $payload = json_encode($event->toArray(), JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);
        $accepted = $this->locked(function () use ($event, $payload): bool {
            if ($this->rows()->where('event_id', $event->id())->lockForUpdate()->first() !== null) {
                return true;
            }
            $state = $this->connection()->table('security_observability_state')->where('id', 1)->lockForUpdate()->first();
            if ($state->stored_rows >= $this->limit('max_rows', 100000)
                || $state->stored_bytes + strlen($payload) > $this->limit('max_bytes', 104857600)) {
                $this->connection()->table('security_observability_state')->where('id', 1)->increment('rejected', 1, ['capacity_rejected' => true]);

                return false;
            }
            $this->rows()->insert(['event_id' => $event->id(), 'payload' => $payload, 'bytes' => strlen($payload),
                'status' => 'pending', 'attempts' => 0, 'created_at' => time(), 'next_attempt' => time()]);
            $this->connection()->table('security_observability_state')->where('id', 1)->update([
                'stored_rows' => $state->stored_rows + 1, 'stored_bytes' => $state->stored_bytes + strlen($payload),
            ]);

            return true;
        });
        if (! $accepted) {
            throw new PersistenceFailed('Outbox capacity exhausted.');
        }
    }

    public function limit(string $key, int $default): int
    {
        return max(1, (int) $this->config->get('security-observability.delivery.'.$key, $default));
    }

    /**
     * Lease one eligible row and increment its attempt count; null means no work is available.
     *
     * @throws LogicException When called inside an existing transaction.
     */
    public function claim(): ?object
    {
        if ($this->connection()->transactionLevel() > 0) {
            throw new LogicException('Export must run outside a business transaction.');
        }

        return $this->locked(function (): ?object {
            $row = $this->rows()->where('status', 'pending')->where('next_attempt', '<=', time())
                ->where(fn (Builder $query) => $query->whereNull('lease_until')->orWhere('lease_until', '<=', time()))
                ->orderBy('created_at')->orderBy('event_id')->lockForUpdate()->first();
            if (! $row) {
                return null;
            }
            $row->lease_token = (string) Str::uuid();
            $row->attempts++;
            $this->rows()->where('event_id', $row->event_id)->update(['lease_token' => $row->lease_token,
                'lease_until' => time() + max($this->limit('lease_seconds', 60), $this->limit('timeout', 10) + 5), 'attempts' => $row->attempts]);

            return $row;
        });
    }

    /**
     * Update a claimed row only while its lease token still matches.
     *
     * @param  'pending'|'delivered'|'quarantined'  $status
     * @param  string|null  $failure  Safe failure code, never an exception message or response body.
     * @param  int  $delay  Seconds until the next attempt.
     */
    public function finish(object $row, string $status, ?string $failure = null, int $delay = 0): void
    {
        $this->locked(function () use ($row, $status, $failure, $delay): void {
            $updated = $this->rows()->where('event_id', $row->event_id)->where('lease_token', $row->lease_token)->update([
                'status' => $status, 'failure' => $failure, 'next_attempt' => time() + $delay,
                'lease_until' => null, 'lease_token' => null, 'delivered_at' => $status === 'delivered' ? time() : null,
            ]);
            if ($updated && $status === 'delivered') {
                $this->connection()->table('security_observability_state')->where('id', 1)->update(['last_success' => time()]);
            }
        });
    }

    /** Reset a quarantined event for delivery, preserving its ID; return the affected row count. */
    public function replay(string $id): int
    {
        return $this->rows()->where('event_id', $id)->where('status', 'quarantined')->update([
            'status' => 'pending', 'attempts' => 0, 'next_attempt' => time(), 'failure' => null,
            'lease_until' => null, 'lease_token' => null,
        ]);
    }

    /** Delete at most 1,000 expired delivered rows; unresolved events are retained. */
    public function prune(): int
    {
        return $this->locked(function (): int {
            $query = $this->rows()->where('status', 'delivered')
                ->where('delivered_at', '<=', time() - $this->limit('retention_seconds', 604800));
            $expired = $query->orderBy('event_id')->limit(1000)->lockForUpdate()->get(['event_id', 'bytes']);
            $deleted = $this->rows()->whereIn('event_id', $expired->pluck('event_id'))->delete();
            if ($deleted) {
                $state = $this->connection()->table('security_observability_state')->where('id', 1)->lockForUpdate()->first();
                $this->connection()->table('security_observability_state')->where('id', 1)->update([
                    'capacity_rejected' => false, 'stored_rows' => $state->stored_rows - $deleted,
                    'stored_bytes' => $state->stored_bytes - $expired->sum('bytes'),
                ]);
            }

            return $deleted;
        });
    }

    /** @return array<string, int|bool|null> Storage/backlog counters; timestamps are Unix seconds. */
    public function health(): array
    {
        $state = $this->connection()->table('security_observability_state')->where('id', 1)->first();
        $oldest = $this->rows()->where('status', 'pending')->min('created_at');
        $count = $this->rows()->count();
        $bytes = (int) $this->rows()->sum('bytes');

        return ['backlog' => $this->rows()->where('status', 'pending')->count(),
            'oldest_pending_seconds' => $oldest === null ? null : max(0, time() - (int) $oldest),
            'last_success' => $state->last_success,
            'storage_rejected' => $state->rejected,
            'retries' => $this->rows()->where('attempts', '>', 1)->count(),
            'quarantined' => $this->rows()->where('status', 'quarantined')->count(),
            'rows' => $count, 'bytes' => $bytes,
            'capacity_exhausted' => (bool) $state->capacity_rejected || $count >= $this->limit('max_rows', 100000) || $bytes >= $this->limit('max_bytes', 104857600)];
    }
}
