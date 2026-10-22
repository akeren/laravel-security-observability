<?php

declare(strict_types=1);

namespace Kater\SecurityObservability\Tests\Feature;

use Illuminate\Database\Schema\Blueprint;
use Illuminate\Queue\Events\JobAttempted;
use Illuminate\Queue\Events\JobProcessing;
use Illuminate\Queue\Events\Looping;
use Illuminate\Queue\Jobs\SyncJob;
use Illuminate\Queue\WorkerOptions;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Queue;
use Illuminate\Support\Facades\Schema;
use Kater\SecurityObservability\Context\CorrelationContext;
use Kater\SecurityObservability\Contracts\Event;
use Kater\SecurityObservability\Contracts\EventRecorder;
use Kater\SecurityObservability\Queue\QueueTelemetry;
use Kater\SecurityObservability\TelemetryState;
use Kater\SecurityObservability\Tests\Fixtures\ContextJob;
use Kater\SecurityObservability\Tests\Fixtures\ExporterJob;
use Kater\SecurityObservability\Tests\TelemetryTestCase;
use RuntimeException;

final class QueueTelemetryTest extends TelemetryTestCase
{
    public function test_nested_sync_failure_restores_parent_context(): void
    {
        ContextJob::$seen = [];
        $context = $this->app->make(CorrelationContext::class);
        $context->start('synthetic-workflow', 'synthetic-request');
        $previous = $context->snapshot();
        Queue::connection('sync')->pushOn('test', new ContextJob(nested: true));
        self::assertSame($previous, $context->snapshot());
        self::assertCount(3, ContextJob::$seen);
        foreach (ContextJob::$seen as $seen) {
            self::assertSame($previous, $seen);
        }
        self::assertSame(['queue.job.processing', 'queue.job.processing', 'queue.job.exception', 'queue.job.failed', 'queue.job.processed'], array_column($this->sink->events, 'name'));
        self::assertNotSame($this->sink->events[0]['attributes']['queue']['attempt_id'], $this->sink->events[1]['attributes']['queue']['attempt_id']);
        self::assertStringNotContainsString('synthetic-job-secret', json_encode($this->sink->events));
    }

    public function test_payload_is_versioned_bounded_and_ignores_non_allowlisted_fields(): void
    {
        $context = $this->app->make(CorrelationContext::class);
        $context->start('workflow', 'request', ['trace_id' => str_repeat('a', 32), 'span_id' => str_repeat('b', 16)]);
        $payload = $this->app->make(QueueTelemetry::class)->payload(['displayName' => ContextJob::class]);
        self::assertSame(1, $payload['security_observability']['version']);
        self::assertLessThan(1024, strlen(json_encode($payload['security_observability'])));
        self::assertSame(['version', 'correlation_id', 'request_id', 'trace_id', 'span_id'], array_keys($payload['security_observability']));
    }

    public function test_exporter_jobs_and_their_requests_are_not_instrumented(): void
    {
        Http::fake(['*' => Http::response('ok')]);
        Queue::connection('sync')->push(new ExporterJob);
        self::assertSame([], $this->sink->events);
        self::assertFalse($this->app->make(TelemetryState::class)->suppressed());
        Queue::connection('sync')->push(new ContextJob);
        self::assertCount(2, $this->sink->events);
    }

    public function test_real_database_queue_retry_and_terminal_failure_keep_correlation_and_clear_context(): void
    {
        config(['queue.connections.telemetry-test' => ['driver' => 'database', 'connection' => 'testing', 'table' => 'jobs', 'queue' => 'default', 'retry_after' => 90]]);
        Schema::create('jobs', function (Blueprint $table): void {
            $table->bigIncrements('id');
            $table->string('queue');
            $table->longText('payload');
            $table->unsignedTinyInteger('attempts');
            $table->unsignedInteger('reserved_at')->nullable();
            $table->unsignedInteger('available_at');
            $table->unsignedInteger('created_at');
        });
        $context = $this->app->make(CorrelationContext::class);
        $context->start('retry-workflow', 'retry-request');
        Queue::connection('telemetry-test')->push(new ContextJob(fail: true));
        self::assertSame(['queue.job.queueing', 'queue.job.queued'], array_column($this->sink->events, 'name'));
        $context->clear();
        $attemptIds = [];
        for ($attempt = 1; $attempt <= 2; $attempt++) {
            $job = Queue::connection('telemetry-test')->pop();
            self::assertNotNull($job);
            try {
                $this->app->make('queue.worker')->process('telemetry-test', $job, new WorkerOptions(maxTries: 2, backoff: 0));
                self::fail('Expected job failure');
            } catch (RuntimeException $error) {
                self::assertSame('synthetic-job-secret', $error->getMessage());
            }
            self::assertSame([], $context->snapshot());
            $processing = array_values(array_filter($this->sink->events, fn ($e) => $e['name'] === 'queue.job.processing'));
            $attemptIds[] = $processing[$attempt - 1]['attributes']['queue']['attempt_id'];
            if ($attempt === 1) {
                self::assertNotContains('queue.job.failed', array_column($this->sink->events, 'name'));
            }
        }
        self::assertNotSame($attemptIds[0], $attemptIds[1]);
        self::assertCount(1, array_filter($this->sink->events, fn ($e) => $e['name'] === 'queue.job.failed'));
        foreach ($this->sink->events as $event) {
            self::assertSame('retry-workflow', $event['correlation_id']);
        }
        self::assertNull(Queue::connection('telemetry-test')->pop());
        $this->app['events']->dispatch(new Looping('telemetry-test', 'default'));
        Queue::connection('sync')->push(new ContextJob);
        self::assertNotSame('retry-workflow', $this->sink->events[array_key_last($this->sink->events)]['correlation_id']);
        self::assertSame([], $context->snapshot());
    }

    public function test_malformed_payload_and_logger_failure_do_not_leak_previous_context(): void
    {
        $context = $this->app->make(CorrelationContext::class);
        $context->start('parent', 'parent-request');
        $this->app->bind(EventRecorder::class, fn () => new class implements EventRecorder
        {
            public function record(Event $event): void
            {
                throw new RuntimeException('sink failure');
            }
        });
        foreach ([['version' => 99, 'correlation_id' => 'bad-version'], ['version' => 1, 'correlation_id' => str_repeat('a', 2000)], ['version' => 1, 'correlation_id' => ['invalid-type']]] as $metadata) {
            $job = new SyncJob($this->app, json_encode(['displayName' => ContextJob::class, 'security_observability' => $metadata]), 'sync', 'test');
            $this->app['events']->dispatch(new JobProcessing('sync', $job));
            self::assertNotSame('parent', $context->snapshot()['correlation_id']);
            self::assertNotSame('bad-version', $context->snapshot()['correlation_id']);
            $this->app['events']->dispatch(new JobAttempted('sync', $job));
            self::assertSame('parent', $context->snapshot()['correlation_id']);
        }
        self::assertSame(3, $this->app->make(TelemetryState::class)->failures);
    }
}
