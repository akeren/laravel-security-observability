<?php

declare(strict_types=1);

namespace Kater\SecurityObservability\Delivery;

use Illuminate\Contracts\Config\Repository;
use Random\Randomizer;

final class RetryPolicy implements \Kater\SecurityObservability\Contracts\RetryPolicy
{
    public function __construct(private Repository $config, private Randomizer $random = new Randomizer) {}

    public function attempts(): int
    {
        return max(1, (int) $this->config->get('security-observability.delivery.max_attempts', 10));
    }

    /** Return bounded jittered backoff in seconds; Retry-After cannot exceed the configured cap. */
    public function delay(int $attempts, ?string $retryAfter): int
    {
        $cap = max(1, min(86400, (int) $this->config->get('security-observability.delivery.max_backoff', 3600)));
        $base = min($cap, max(1, (int) $this->config->get('security-observability.delivery.base_backoff', 5)) * (2 ** max(0, min(17, $attempts - 1))));
        $delay = $this->random->getInt((int) max(1, ceil($base / 2)), (int) $base);
        if ($retryAfter !== null && strlen($retryAfter) <= 128 && ! str_contains($retryAfter, "\0")) {
            $date = \DateTimeImmutable::createFromFormat('D, d M Y H:i:s \G\M\T', $retryAfter, new \DateTimeZone('UTC'));
            $seconds = ctype_digit($retryAfter) ? (int) $retryAfter
                : ($date !== false && $date->format('D, d M Y H:i:s \G\M\T') === $retryAfter ? max(0, $date->getTimestamp() - time()) : 0);
            $delay = max($delay, min($cap, $seconds));
        }

        return $delay;
    }
}
