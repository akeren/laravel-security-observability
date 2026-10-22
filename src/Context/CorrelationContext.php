<?php

declare(strict_types=1);

namespace Kater\SecurityObservability\Context;

use Illuminate\Support\Str;

/** Sequential request/job scope. Concurrent runtimes are not supported yet. */
final class CorrelationContext
{
    private array $state = [];

    public static function validId(mixed $value): ?string
    {
        return is_string($value) && preg_match('/\A[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\z/D', $value) === 1 ? $value : null;
    }

    /**
     * Replace the current scope, generating IDs for missing or invalid inputs.
     *
     * @param  array{trace_id?: string, span_id?: string}  $trace  Existing trace context; both IDs must be valid.
     */
    public function start(?string $correlationId = null, ?string $requestId = null, array $trace = []): void
    {
        $this->state = [
            'correlation_id' => self::validId($correlationId) ?? (string) Str::uuid(),
            'request_id' => self::validId($requestId) ?? (string) Str::uuid(),
        ];
        if (isset($trace['trace_id'], $trace['span_id'])
            && is_string($trace['trace_id']) && is_string($trace['span_id'])
            && preg_match('/\A[0-9a-f]{32}\z/', $trace['trace_id'])
            && preg_match('/\A[0-9a-f]{16}\z/', $trace['span_id'])
            && trim($trace['trace_id'], '0') !== '' && trim($trace['span_id'], '0') !== '') {
            $this->state += array_intersect_key($trace, array_flip(['trace_id', 'span_id']));
        }
    }

    /** @return array{correlation_id?: string, request_id?: string, trace_id?: string, span_id?: string} */
    public function snapshot(): array
    {
        return $this->state;
    }

    public function restore(array $snapshot): void
    {
        if ($snapshot === []) {
            $this->clear();

            return;
        }
        $this->start(self::validId($snapshot['correlation_id'] ?? null), self::validId($snapshot['request_id'] ?? null), $snapshot);
    }

    public function clear(): void
    {
        $this->state = [];
    }

    /**
     * Run in a temporary scope, restoring the previous state even when the callback throws.
     *
     * @template T
     *
     * @param  array<string, string>  $snapshot
     * @param  callable(): T  $callback
     * @return T
     */
    public function within(array $snapshot, callable $callback): mixed
    {
        $previous = $this->snapshot();
        $this->restore($snapshot);
        try {
            return $callback();
        } finally {
            $this->restore($previous);
        }
    }
}
