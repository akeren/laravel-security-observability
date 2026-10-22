<?php

declare(strict_types=1);

namespace Kater\SecurityObservability\Tests\Feature;

use Illuminate\Auth\Events\Login;
use Illuminate\Auth\GenericUser;
use Illuminate\Http\Client\Factory;
use Kater\SecurityObservability\Contracts\EventRecorder;
use Kater\SecurityObservability\Delivery\Exporter;
use Kater\SecurityObservability\Delivery\ExportOutbox;
use Kater\SecurityObservability\Delivery\Outbox;
use Kater\SecurityObservability\Delivery\PersistenceFailed;
use Kater\SecurityObservability\Events\OperationalEvent;
use Kater\SecurityObservability\Events\SecurityEvent;
use Kater\SecurityObservability\TelemetryState;
use Kater\SecurityObservability\Tests\TestCase;
use Symfony\Component\Process\Process;

class DeliveryTest extends TestCase
{
    protected function defineEnvironment($app): void
    {
        $app['config']->set('database.default', 'testing');
        $app['config']->set('database.connections.testing', ['driver' => 'sqlite', 'database' => ':memory:', 'prefix' => '']);
        $app['config']->set('security-observability.enabled', true);
        $app['config']->set('security-observability.delivery.driver', 'outbox');
        $app['config']->set('security-observability.delivery.endpoint', 'https://collector.example/events');
    }

    protected function setUp(): void
    {
        parent::setUp();
        (require __DIR__.'/../../database/migrations/2026_10_18_000000_create_security_observability_outbox.php')->up();
    }

    protected function record(): SecurityEvent
    {
        $event = new SecurityEvent('security.test', 'observe', attributes: ['password' => 'synthetic-secret']);
        $this->app->make(EventRecorder::class)->record($event);

        return $event;
    }

    protected function outbox(): Outbox
    {
        return $this->app->make(Outbox::class);
    }

    public function test_only_sanitized_payload_is_persisted_and_duplicate_recording_keeps_original(): void
    {
        $event = $this->record();
        $first = $this->outbox()->rows()->first();
        $this->app->make(EventRecorder::class)->record($event);
        self::assertSame(1, $this->outbox()->rows()->count());
        self::assertSame($first->payload, $this->outbox()->rows()->first()->payload);
        self::assertStringNotContainsString('synthetic-secret', $first->payload);
        self::assertSame('[REDACTED]', json_decode($first->payload, true)['attributes']['password']);
    }

    public function test_outbox_rolls_back_with_business_transaction_and_commits_with_it(): void
    {
        $db = $this->app['db']->connection();
        $db->beginTransaction();
        $this->record();
        self::assertSame(1, $this->outbox()->rows()->count());
        $db->rollBack();
        self::assertSame(0, $this->outbox()->rows()->count());
        $db->transaction(fn () => $this->record());
        self::assertSame(1, $this->outbox()->rows()->count());
    }

    public function test_leases_exclude_other_workers_recover_after_crash_and_fence_stale_acknowledgments(): void
    {
        $this->record();
        $old = $this->outbox()->claim();
        self::assertNull($this->outbox()->claim());
        $this->outbox()->rows()->update(['lease_until' => time() - 1]);
        $restarted = $this->app->make(Outbox::class);
        $new = $restarted->claim();
        self::assertSame($old->event_id, $new->event_id);
        self::assertNotSame($old->lease_token, $new->lease_token);
        self::assertSame(2, $new->attempts);
        $this->outbox()->finish($old, 'delivered');
        self::assertSame('pending', $restarted->rows()->first()->status);
        $restarted->finish($new, 'delivered');
        self::assertSame('delivered', $restarted->rows()->first()->status);
    }

    public function test_rate_limit_retries_preserve_payload_and_id_and_exporter_does_not_record_itself(): void
    {
        $event = $this->record();
        $http = $this->app->make(Factory::class);
        $http->fakeSequence()->push('synthetic-secret', 429, ['Retry-After' => '120'])->push('', 202);
        self::assertSame(1, $this->app->make(Exporter::class)->run());
        $row = $this->outbox()->rows()->first();
        self::assertSame('pending', $row->status);
        self::assertSame('http_429', $row->failure);
        self::assertGreaterThanOrEqual(time() + 119, $row->next_attempt);
        self::assertSame(0, $this->app->make(Exporter::class)->run());
        $this->outbox()->rows()->update(['next_attempt' => time() - 1]);
        self::assertSame(1, $this->app->make(Exporter::class)->run());
        self::assertSame('delivered', $this->outbox()->rows()->first()->status);
        self::assertSame(1, $this->outbox()->rows()->count());
        $http->assertSentCount(2);
        foreach ($http->recorded() as [$request]) {
            self::assertSame([$event->id()], $request->header('Idempotency-Key'));
            self::assertSame($row->payload, $request->body());
            self::assertFalse($request->hasHeader('X-Correlation-ID'));
        }
        self::assertFalse($this->app->make(TelemetryState::class)->suppressed());
    }

    public function test_network_failure_is_bounded_and_eventually_quarantined(): void
    {
        config(['security-observability.delivery.max_attempts' => 2]);
        $this->record();
        $http = $this->app->make(Factory::class);
        $http->fake(fn () => $http->failedConnection('synthetic-secret'));
        $this->app->make(Exporter::class)->run();
        self::assertSame('pending', $this->outbox()->rows()->first()->status);
        $this->outbox()->rows()->update(['next_attempt' => time() - 1]);
        $this->app->make(Exporter::class)->run();
        $row = $this->outbox()->rows()->first();
        self::assertSame('quarantined', $row->status);
        self::assertSame('connection', $row->failure);
        self::assertStringNotContainsString('synthetic-secret', json_encode($row));
    }

    public function test_permanent_failure_can_be_inspected_and_replayed_without_changing_id(): void
    {
        $event = $this->record();
        $http = $this->app->make(Factory::class);
        $http->fakeSequence()->push('synthetic-secret', 400)->push('', 200);
        $this->artisan('security-observability:delivery export')->assertSuccessful();
        self::assertSame('quarantined', $this->outbox()->rows()->first()->status);
        $this->artisan('security-observability:delivery inspect')->doesntExpectOutputToContain('synthetic-secret')->doesntExpectOutputToContain('payload')->assertSuccessful();
        $this->artisan('security-observability:delivery health')->assertFailed();
        $this->artisan('security-observability:delivery', ['action' => 'replay', '--id' => $event->id()])->assertSuccessful();
        $this->artisan('security-observability:delivery export')->assertSuccessful();
        self::assertSame($event->id(), $this->outbox()->rows()->first()->event_id);
        self::assertSame('delivered', $this->outbox()->rows()->first()->status);
        $this->artisan('security-observability:delivery health')->assertSuccessful();
    }

    public function test_capacity_fail_open_and_strict_security_policies_are_distinct(): void
    {
        config(['security-observability.delivery.max_rows' => 1]);
        $this->record();
        $this->record();
        self::assertSame(1, $this->app->make(TelemetryState::class)->failures);
        self::assertTrue($this->outbox()->health()['capacity_exhausted']);
        self::assertSame(1, $this->outbox()->health()['storage_rejected']);
        config(['security-observability.delivery.strict_security' => true]);
        $this->app->make(EventRecorder::class)->record(new OperationalEvent('operation.test'));
        try {
            $this->record();
            self::fail('Strict security must report persistence failure.');
        } catch (PersistenceFailed $error) {
            self::assertStringNotContainsString('synthetic-secret', $error->getMessage());
        }
        self::assertFalse($this->app->make(TelemetryState::class)->suppressed());
        self::assertSame(1, $this->outbox()->rows()->count());
    }

    public function test_byte_limit_and_missing_storage_are_visible_without_leaking_exceptions(): void
    {
        config(['security-observability.delivery.max_bytes' => 1]);
        $this->record();
        self::assertSame(0, $this->outbox()->rows()->count());
        $this->artisan('security-observability:delivery health')->assertFailed();
        $this->app['db']->connection()->getSchemaBuilder()->drop('security_observability_outbox');
        $this->record();
        self::assertSame(2, $this->app->make(TelemetryState::class)->failures);
        $this->artisan('security-observability:delivery health')->expectsOutputToContain('Delivery unavailable')->assertFailed();
    }

    public function test_strict_failure_rolls_back_host_mutation_and_propagates_through_auth_listener(): void
    {
        config(['security-observability.delivery.max_bytes' => 1, 'security-observability.delivery.strict_security' => true]);
        $db = $this->app['db']->connection();
        try {
            $db->transaction(function () use ($db): void {
                $db->table('security_observability_state')->where('id', 1)->update(['last_success' => 123]);
                $this->app['events']->dispatch(new Login('web', new GenericUser(['id' => 'user-1']), false));
            });
            self::fail('Strict failure should escape the listener.');
        } catch (PersistenceFailed) {
            self::assertNull($db->table('security_observability_state')->value('last_success'));
        }
        self::assertFalse($this->app->make(TelemetryState::class)->suppressed());
    }

    public function test_pruning_never_removes_unresolved_events_and_preserves_health_success(): void
    {
        $this->record();
        $row = $this->outbox()->claim();
        $this->outbox()->finish($row, 'delivered');
        $this->outbox()->rows()->where('event_id', $row->event_id)->update(['delivered_at' => time() - 700000]);
        $this->record();
        $pending = $this->outbox()->claim();
        $this->outbox()->finish($pending, 'quarantined', 'http_400');
        $this->record();
        $this->artisan('security-observability:delivery prune')->assertSuccessful();
        self::assertSame(2, $this->outbox()->rows()->count());
        self::assertNotNull($this->outbox()->health()['last_success']);
    }

    public function test_insecure_endpoint_is_rejected_before_claiming_and_disabled_export_is_idle(): void
    {
        $this->record();
        config(['security-observability.delivery.endpoint' => 'http://collector.example']);
        $this->artisan('security-observability:delivery export')->assertFailed();
        self::assertSame(0, $this->outbox()->rows()->first()->attempts);
        config(['security-observability.enabled' => false]);
        self::assertSame(0, $this->app->make(Exporter::class)->run());
    }

    public function test_export_job_is_excluded_and_batch_size_limits_work(): void
    {
        config(['security-observability.delivery.batch_size' => 1]);
        $this->record();
        $this->record();
        $http = $this->app->make(Factory::class);
        $http->fake(['*' => $http->response('', 200)]);
        $this->app['queue']->connection('sync')->push(new ExportOutbox);
        self::assertSame(2, $this->outbox()->rows()->count());
        self::assertSame(1, $this->outbox()->rows()->where('status', 'delivered')->count());
        $http->assertSentCount(1);
        self::assertFalse($this->app->make(TelemetryState::class)->suppressed());
    }

    public function test_server_errors_and_redirects_have_safe_transport_options(): void
    {
        config(['security-observability.delivery.token' => 'synthetic-auth', 'security-observability.delivery.max_backoff' => 60]);
        $this->record();
        $http = $this->app->make(Factory::class);
        $optionsSeen = [];
        $http->fake(function ($request, $options) use ($http, &$optionsSeen) {
            $optionsSeen[] = $options;

            return count($optionsSeen) === 1
                ? $http->response('', 503, ['Retry-After' => '999999'])
                : $http->response('', 302, ['Location' => 'https://other.example']);
        });
        $this->app->make(Exporter::class)->run();
        self::assertLessThanOrEqual(time() + 60, $this->outbox()->rows()->first()->next_attempt);
        $this->outbox()->rows()->update(['next_attempt' => time() - 1]);
        $this->app->make(Exporter::class)->run();
        self::assertSame('quarantined', $this->outbox()->rows()->first()->status);
        foreach ($optionsSeen as $options) {
            self::assertTrue($options['verify']);
            self::assertFalse($options['allow_redirects']);
            self::assertSame(10, $options['timeout']);
            self::assertSame(3, $options['connect_timeout']);
        }
        $http->assertSentCount(2);
    }

    public function test_strict_security_rejects_oversized_event_before_persistence(): void
    {
        config(['security-observability.delivery.strict_security' => true, 'security-observability.privacy.max_event_bytes' => 256]);
        $this->expectException(PersistenceFailed::class);
        $this->record();
    }

    public function test_export_cannot_deliver_uncommitted_events(): void
    {
        $db = $this->app['db']->connection();
        $db->beginTransaction();
        try {
            $this->record();
            $this->artisan('security-observability:delivery export')->assertFailed();
            self::assertSame(0, $this->outbox()->rows()->first()->attempts);
        } finally {
            $db->rollBack();
        }
        self::assertSame(0, $this->outbox()->rows()->count());
    }

    public function test_independent_connection_preserves_observation_across_business_rollback(): void
    {
        config(['database.connections.observations' => ['driver' => 'sqlite', 'database' => ':memory:', 'prefix' => ''],
            'security-observability.delivery.connection' => 'observations']);
        (require __DIR__.'/../../database/migrations/2026_10_18_000000_create_security_observability_outbox.php')->up();
        $db = $this->app['db']->connection();
        $db->beginTransaction();
        $this->record();
        $db->rollBack();
        self::assertSame(1, $this->outbox()->rows()->count());
        self::assertSame(0, $db->table('security_observability_outbox')->count());
    }

    public function test_unexpected_transport_error_does_not_leak_credentials_and_lease_is_recoverable(): void
    {
        $this->record();
        $this->app->make(Factory::class)->fake(function () {
            throw new \RuntimeException('synthetic-secret');
        });
        try {
            $this->app->make(Exporter::class)->run();
            self::fail('Unexpected transport failure must be reported.');
        } catch (\RuntimeException $error) {
            self::assertStringNotContainsString('synthetic-secret', $error->getMessage());
            self::assertNull($error->getPrevious());
        }
        self::assertSame('pending', $this->outbox()->rows()->first()->status);
        self::assertNotNull($this->outbox()->rows()->first()->lease_until);
        self::assertFalse($this->app->make(TelemetryState::class)->suppressed());
    }

    public function test_concurrent_processes_claim_each_persisted_event_once(): void
    {
        $path = tempnam(sys_get_temp_dir(), 'outbox-concurrency-');
        $script = tempnam(sys_get_temp_dir(), 'outbox-worker-');
        $processes = [];
        try {
            config(['database.connections.concurrent' => ['driver' => 'sqlite', 'database' => $path, 'prefix' => '', 'busy_timeout' => 5000],
                'security-observability.delivery.connection' => 'concurrent']);
            (require __DIR__.'/../../database/migrations/2026_10_18_000000_create_security_observability_outbox.php')->up();
            for ($i = 0; $i < 12; $i++) {
                $this->record();
            }
            file_put_contents($script, <<<'PHP'
<?php
require $argv[1];
$capsule = new Illuminate\Database\Capsule\Manager;
$capsule->addConnection(['driver' => 'sqlite', 'database' => $argv[2], 'prefix' => '', 'busy_timeout' => 5000]);
$config = new Illuminate\Config\Repository;
$outbox = new Kater\SecurityObservability\Delivery\Outbox($capsule->getDatabaseManager(), $config);
while ($row = $outbox->claim()) {
    usleep(10000);
    $outbox->finish($row, 'delivered');
    echo $row->event_id."\n";
}
PHP);
            for ($i = 0; $i < 2; $i++) {
                $process = new Process([PHP_BINARY, $script, dirname(__DIR__, 2).'/vendor/autoload.php', $path]);
                $process->setTimeout(20);
                $process->start();
                $processes[] = $process;
            }
            $ids = [];
            foreach ($processes as $process) {
                $process->wait();
                self::assertTrue($process->isSuccessful(), $process->getErrorOutput());
                $ids = [...$ids, ...array_filter(explode("\n", trim($process->getOutput())))];
            }
            self::assertCount(12, $ids);
            self::assertCount(12, array_unique($ids));
            self::assertSame(12, $this->outbox()->rows()->where('status', 'delivered')->count());
        } finally {
            foreach ($processes as $process) {
                $process->stop();
            }
            $this->app['db']->purge('concurrent');
            unlink($path);
            unlink($script);
        }
    }
}
