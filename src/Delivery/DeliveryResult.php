<?php

declare(strict_types=1);

namespace Kater\SecurityObservability\Delivery;

/** A transport outcome contains only safe failure codes and an optional Retry-After value. */
final readonly class DeliveryResult
{
    private function __construct(public string $status, public ?string $failure = null, public ?string $retryAfter = null) {}

    public static function delivered(): self
    {
        return new self('delivered');
    }

    public static function retry(string $failure, ?string $retryAfter = null): self
    {
        return new self('pending', $failure, $retryAfter);
    }

    public static function quarantine(string $failure): self
    {
        return new self('quarantined', $failure);
    }
}
