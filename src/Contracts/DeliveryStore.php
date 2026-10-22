<?php

declare(strict_types=1);

namespace Kater\SecurityObservability\Contracts;

/** Lease operations needed by an exporter, independent of storage administration. */
interface DeliveryStore
{
    /** @return object{event_id: string, payload: string, attempts: int, lease_token: string}|null */
    public function claim(): ?object;

    /**
     * Update only if the claimed row's lease token is still current.
     *
     * @param  'pending'|'delivered'|'quarantined'  $status
     * @param  string|null  $failure  Safe failure code, never raw response or exception text.
     * @param  int  $delay  Seconds until retry.
     */
    public function finish(object $row, string $status, ?string $failure = null, int $delay = 0): void;
}
