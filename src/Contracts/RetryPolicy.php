<?php

declare(strict_types=1);

namespace Kater\SecurityObservability\Contracts;

interface RetryPolicy
{
    /** Maximum number of delivery attempts per event. */
    public function attempts(): int;

    /** Bounded retry delay in seconds; untrusted Retry-After values must not bypass the cap. */
    public function delay(int $attempts, ?string $retryAfter): int;
}
