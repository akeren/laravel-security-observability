<?php

declare(strict_types=1);

namespace Kater\SecurityObservability\Events;

use DateTimeImmutable;
use DateTimeZone;
use Illuminate\Support\Str;
use InvalidArgumentException;
use Kater\SecurityObservability\Contracts\Event;

final readonly class SecurityEvent implements Event
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
        public string $action,
        public Outcome $outcome = Outcome::Unknown,
        public Severity $severity = Severity::Informational,
        public ?Actor $actor = null,
        public ?Target $target = null,
        public ?Tenant $tenant = null,
        public array $attributes = [],
    ) {
        if (! preg_match('/\A[a-z][a-z0-9_.]{0,127}\z/', $name)
            || ! preg_match('/\A[a-z][a-z0-9_.-]{0,63}\z/', $action)) {
            throw new InvalidArgumentException('Security events require a stable name and action.');
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
        return [
            'event_id' => $this->id(), 'occurred_at' => $this->occurredAt,
            'kind' => 'security', 'name' => $this->name, 'action' => $this->action,
            'outcome' => $this->outcome->value, 'severity' => $this->severity->value,
            'actor' => $this->actor?->toArray(), 'target' => $this->target?->toArray(),
            'tenant' => $this->tenant?->toArray(), 'attributes' => $this->attributes,
        ];
    }
}
