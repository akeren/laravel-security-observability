<?php

declare(strict_types=1);

namespace Kater\SecurityObservability\Security;

use Kater\SecurityObservability\Contracts\EventRecorder;
use Kater\SecurityObservability\Delivery\PersistenceFailed;
use Kater\SecurityObservability\Events\Actor;
use Kater\SecurityObservability\Events\Outcome;
use Kater\SecurityObservability\Events\SecurityEvent;
use Kater\SecurityObservability\Events\Severity;
use Kater\SecurityObservability\Events\Target;
use Kater\SecurityObservability\Events\Tenant;

/** Convenience API for host-observed security actions. */
final class SecurityEvents
{
    public function __construct(private EventRecorder $recorder) {}

    public function record(SecurityEvent $event): void
    {
        $this->recorder->record($event);
    }

    /**
     * Record a host-observed outcome without inferring actor or tenant identity.
     *
     * @param  array<string, mixed>  $attributes
     *
     * @throws PersistenceFailed When strict security persistence fails.
     */
    public function emit(SecurityAction $action, Outcome $outcome, ?Actor $actor = null,
        ?Target $target = null, ?Tenant $tenant = null, array $attributes = [],
        Severity $severity = Severity::Informational): void
    {
        $this->record(new SecurityEvent($action->value, $action->action(), $outcome, $severity, $actor, $target, $tenant, $attributes));
    }
}
