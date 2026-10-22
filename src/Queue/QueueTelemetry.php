<?php

declare(strict_types=1);

namespace Kater\SecurityObservability\Queue;

use Illuminate\Container\Container;
use Illuminate\Contracts\Config\Repository;
use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Contracts\Queue\Job;
use Illuminate\Queue\Events\JobAttempted;
use Illuminate\Queue\Events\JobExceptionOccurred;
use Illuminate\Queue\Events\JobFailed;
use Illuminate\Queue\Events\JobProcessed;
use Illuminate\Queue\Events\JobProcessing;
use Illuminate\Queue\Events\JobQueued;
use Illuminate\Queue\Events\JobQueueing;
use Illuminate\Queue\Events\Looping;
use Illuminate\Queue\Queue;
use Illuminate\Support\Str;
use Kater\SecurityObservability\Context\CorrelationContext;
use Kater\SecurityObservability\Contracts\EventRecorder;
use Kater\SecurityObservability\Events\OperationalEvent;
use Kater\SecurityObservability\TelemetryState;
use Throwable;
use WeakMap;

final class QueueTelemetry
{
    private bool $registered = false;

    private WeakMap $jobs;

    public function __construct(private Container $app, private Repository $config, private TelemetryState $state)
    {
        $this->jobs = new WeakMap;
    }

    public function register(Dispatcher $events): void
    {
        if ($this->registered) {
            return;
        }
        $this->registered = true;
        // The framework hook is static: resolve the current application, never retain an old container.
        Queue::createPayloadUsing(static function ($connection, $queue, $payload): array {
            $app = Container::getInstance();

            return $app->bound(self::class) ? $app->make(self::class)->payload($payload) : [];
        });
        $events->listen(JobProcessing::class, fn ($event) => $this->safely(fn () => $this->begin($event)));
        foreach ([JobProcessed::class => 'processed', JobExceptionOccurred::class => 'exception', JobFailed::class => 'failed'] as $class => $name) {
            $events->listen($class, fn ($event) => $this->safely(fn () => $this->jobEvent($event, $name)));
        }
        // Both sync and worker queues emit this in finally, including retriable exceptions.
        $events->listen(JobAttempted::class, fn ($event) => $this->finish($event->job));
        foreach ([JobQueueing::class => 'queueing', JobQueued::class => 'queued'] as $class => $name) {
            $events->listen($class, fn ($event) => $this->safely(fn () => $this->dispatchEvent($event, $name)));
        }
        $events->listen(Looping::class, fn () => $this->reset());
    }

    public function payload(array $payload): array
    {
        try {
            if (! $this->enabled() || $this->state->suppressed() || $this->excluded($payload)) {
                return [];
            }
            $context = $this->context();
            $snapshot = $context->snapshot();
            if ($snapshot === []) {
                $context->start();
                $snapshot = $context->snapshot();
                $context->clear();
            }

            return ['security_observability' => ['version' => 1, ...$snapshot]];
        } catch (Throwable) {
            $this->state->failures++;

            return [];
        }
    }

    public function reset(): void
    {
        foreach ($this->jobs as $job => $data) {
            if ($data['suppressed']) {
                $this->state->leave();
            }
        }
        $this->jobs = new WeakMap;
        $this->context()->clear();
    }

    private function begin(JobProcessing $event): void
    {
        if (! $this->enabled()) {
            return;
        }
        $context = $this->context();
        $suppressed = $this->state->suppressed() || $this->excluded($event->job->payload());
        $this->jobs[$event->job] = ['context' => $context, 'previous' => $context->snapshot(),
            'started' => hrtime(true), 'attempt_id' => (string) Str::uuid(), 'suppressed' => $suppressed];
        if ($suppressed) {
            $this->state->enter();

            return;
        }
        $this->activate($event->job->payload());
        $this->jobEvent($event, 'processing');
    }

    private function jobEvent(object $event, string $name): void
    {
        if (! $this->enabled() || $this->state->suppressed() || $this->excluded($event->job->payload())) {
            return;
        }
        $data = $this->jobs[$event->job] ?? null;
        $emit = function () use ($event, $name, $data): void {
            $failure = in_array($name, ['exception', 'failed'], true);
            $this->app->make(EventRecorder::class)->record(new OperationalEvent('queue.job.'.$name, [
                'queue' => ['connection' => $event->connectionName, 'name' => $event->job->getQueue(),
                    'job_name' => $event->job->resolveName(), 'job_id' => $event->job->getJobId(),
                    'attempt' => $event->job->attempts(), 'attempt_id' => $data['attempt_id'] ?? null,
                    'duration_ms' => $data ? round((hrtime(true) - $data['started']) / 1e6, 3) : null,
                    'released' => $event->job->isReleased(), 'failed' => $event->job->hasFailed()],
                'exception_type' => isset($event->exception) ? $event->exception::class : null,
            ], $failure ? 'failure' : ($name === 'processed' && ! $event->job->isReleased() && ! $event->job->hasFailed() ? 'success' : 'unknown'),
                $failure ? ($name === 'failed' ? 'error' : 'warning') : 'informational'));
        };
        if ($data !== null) {
            $emit();

            return;
        }
        $context = $this->context();
        $previous = $context->snapshot();
        try {
            $this->activate($event->job->payload());
            $emit();
        } finally {
            $context->restore($previous);
        }
    }

    private function dispatchEvent(object $event, string $name): void
    {
        $payload = $event->payload();
        if (! $this->enabled() || $this->state->suppressed() || $this->excluded($payload)) {
            return;
        }
        $context = $this->context();
        $previous = $context->snapshot();
        try {
            $this->activate($payload);
            $this->app->make(EventRecorder::class)->record(new OperationalEvent('queue.job.'.$name, [
                'queue' => ['connection' => $event->connectionName, 'name' => $event->queue,
                    'job_name' => $payload['displayName'] ?? null, 'job_id' => $event->id ?? null],
            ]));
        } finally {
            $context->restore($previous);
        }
    }

    private function finish(Job $job): void
    {
        if (! isset($this->jobs[$job])) {
            return;
        }
        $data = $this->jobs[$job];
        unset($this->jobs[$job]);
        try {
            $data['context']->restore($data['previous']);
        } finally {
            if ($data['suppressed']) {
                $this->state->leave();
            }
        }
    }

    private function activate(array $payload): void
    {
        $data = $payload['security_observability'] ?? [];
        if (! is_array($data) || ($data['version'] ?? null) !== 1
            || strlen(json_encode($data, JSON_THROW_ON_ERROR)) > 1024) {
            $data = [];
        }
        $this->context()->start(CorrelationContext::validId($data['correlation_id'] ?? null),
            CorrelationContext::validId($data['request_id'] ?? null), $data);
    }

    private function excluded(array $payload): bool
    {
        $class = $payload['displayName'] ?? '';

        return is_string($class) && (is_a($class, ExcludeFromTelemetry::class, true)
            || in_array($class, $this->config->get('security-observability.queue.excluded_jobs', []), true));
    }

    private function enabled(): bool
    {
        return (bool) $this->config->get('security-observability.enabled') && (bool) $this->config->get('security-observability.queue.enabled');
    }

    private function context(): CorrelationContext
    {
        return $this->app->make(CorrelationContext::class);
    }

    private function safely(callable $callback): void
    {
        try {
            $callback();
        } catch (Throwable) {
            $this->state->failures++;
        }
    }
}
