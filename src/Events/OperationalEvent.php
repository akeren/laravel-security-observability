<?php

declare(strict_types=1);

namespace Kater\SecurityObservability\Events;

use DateTimeImmutable;
use DateTimeZone;
use Illuminate\Support\Str;
use InvalidArgumentException;
use Kater\SecurityObservability\Contracts\Event;

final readonly class OperationalEvent implements Event
{
    private string $eventId;

    private string $occurredAt;

    /**
     * @param  array<string, mixed>  $attributes  Untrusted input normalized by the recorder; never include credential values.
     *
     * @throws InvalidArgumentException When event metadata is invalid.
     */
    public function __construct(
        public string $name,
        public array $attributes = [],
        public string $outcome = 'unknown',
        public string $severity = 'informational',
    ) {
        if (! preg_match('/\A[a-z][a-z0-9_.]{0,127}\z/', $name)
            || ! in_array($outcome, ['success', 'failure', 'unknown'], true)
            || ! in_array($severity, ['informational', 'warning', 'error'], true)) {
            throw new InvalidArgumentException('Invalid operational event metadata.');
        }
        $this->eventId = (string) Str::uuid();
        $this->occurredAt = (new DateTimeImmutable('now', new DateTimeZone('UTC')))->format('Y-m-d\TH:i:s.u\Z');
    }

    public function id(): string
    {
        return $this->eventId;
    }

    public function toArray(): array
    {
        return ['event_id' => $this->id(), 'occurred_at' => $this->occurredAt, 'kind' => 'operational',
            'name' => $this->name, 'action' => $this->name, 'outcome' => $this->outcome,
            'severity' => $this->severity, 'attributes' => $this->attributes];
    }
}
