<?php

declare(strict_types=1);

namespace Kater\SecurityObservability\Tests\Integration;

use Kater\SecurityObservability\Tests\Feature\DeliveryTest;
use LogicException;
use Symfony\Component\Process\Process;

/** Runs the delivery behavior suite against a disposable, explicitly named database. */
final class DatabaseDeliveryTest extends DeliveryTest
{
    protected function defineEnvironment($app): void
    {
        parent::defineEnvironment($app);
        $driver = getenv('SECURITY_TEST_DB_DRIVER');
        if (! in_array($driver, ['mysql', 'pgsql'], true)) {
            throw new LogicException('Set SECURITY_TEST_DB_DRIVER to mysql or pgsql for the disposable integration database.');
        }
        $app['config']->set('database.connections.testing', [
            'driver' => $driver, 'host' => '127.0.0.1',
            'port' => getenv('SECURITY_TEST_DB_PORT') ?: ($driver === 'mysql' ? 13306 : 15432),
            'database' => 'security_observability_test', 'username' => 'telemetry_test',
            'password' => 'synthetic-test-password', 'charset' => $driver === 'mysql' ? 'utf8mb4' : 'utf8',
            'collation' => 'utf8mb4_unicode_ci', 'prefix' => '', 'strict' => true,
        ]);
    }

    protected function tearDown(): void
    {
        try {
            if ($this->app !== null) {
                $db = $this->app['db']->connection('testing');
                while ($db->transactionLevel() > 0) {
                    $db->rollBack();
                }
                config(['security-observability.delivery.connection' => 'testing']);
                (require __DIR__.'/../../database/migrations/2026_10_18_000000_create_security_observability_outbox.php')->down();
            }
        } finally {
            parent::tearDown();
        }
    }

    public function test_independent_connection_preserves_observation_across_business_rollback(): void
    {
        config(['database.connections.observations' => array_replace(config('database.connections.testing'), ['prefix' => 'observations_', 'prefix_indexes' => true]),
            'security-observability.delivery.connection' => 'observations']);
        $migration = require __DIR__.'/../../database/migrations/2026_10_18_000000_create_security_observability_outbox.php';
        $migration->down();
        try {
            $migration->up();
            $business = $this->app['db']->connection('testing');
            $business->beginTransaction();
            $business->table('security_observability_state')->increment('rejected');
            $this->record();
            $business->rollBack();
            self::assertSame(1, $this->outbox()->rows()->count());
            self::assertSame(0, $business->table('security_observability_outbox')->count());
            self::assertSame(0, (int) $business->table('security_observability_state')->value('rejected'));
        } finally {
            $migration->down();
            config(['security-observability.delivery.connection' => 'testing']);
        }
    }

    public function test_concurrent_processes_claim_each_persisted_event_once(): void
    {
        for ($i = 0; $i < 12; $i++) {
            $this->record();
        }
        $output = $this->workers('claim');
        $ids = array_merge(...array_map(fn ($text) => array_filter(explode("\n", trim($text))), $output));
        self::assertCount(12, $ids);
        self::assertCount(12, array_unique($ids));
        self::assertSame(12, $this->outbox()->rows()->where('status', 'delivered')->count());
    }

    public function test_concurrent_writers_cannot_exceed_capacity(): void
    {
        $output = $this->workers('write');
        self::assertSame(3, array_sum(array_map('intval', $output)));
        self::assertSame(3, $this->outbox()->rows()->count());
        $state = $this->app['db']->connection()->table('security_observability_state')->first();
        self::assertSame(3, (int) $state->stored_rows);
        self::assertSame(21, (int) $state->rejected);
        self::assertSame((int) $this->outbox()->rows()->sum('bytes'), (int) $state->stored_bytes);
    }

    /** @return list<string> */
    private function workers(string $operation): array
    {
        $script = tempnam(sys_get_temp_dir(), 'delivery-db-worker-');
        $processes = [];
        try {
            file_put_contents($script, <<<'PHP'
<?php
require $argv[1];
$capsule = new Illuminate\Database\Capsule\Manager;
$capsule->addConnection(json_decode($argv[2], true, flags: JSON_THROW_ON_ERROR));
$config = new Illuminate\Config\Repository(['security-observability' => ['delivery' => ['max_rows' => 3]]]);
$outbox = new Kater\SecurityObservability\Delivery\Outbox($capsule->getDatabaseManager(), $config);
if ($argv[3] === 'write') {
    $accepted = 0;
    for ($i = 0; $i < 12; $i++) {
        try {
            $outbox->write(new Kater\SecurityObservability\Events\SanitizedEvent(json_encode(['event_id' => bin2hex(random_bytes(16))], JSON_THROW_ON_ERROR)));
            $accepted++;
        } catch (Kater\SecurityObservability\Delivery\PersistenceFailed) {
        }
    }
    echo $accepted;
} else {
    while ($row = $outbox->claim()) {
        usleep(10000);
        $outbox->finish($row, 'delivered');
        echo $row->event_id."\n";
    }
}
PHP);
            for ($i = 0; $i < 2; $i++) {
                $process = new Process([PHP_BINARY, $script, dirname(__DIR__, 2).'/vendor/autoload.php',
                    json_encode(config('database.connections.testing'), JSON_THROW_ON_ERROR), $operation]);
                $process->setTimeout(30);
                $process->start();
                $processes[] = $process;
            }
            $output = [];
            foreach ($processes as $process) {
                $process->wait();
                self::assertTrue($process->isSuccessful(), $process->getErrorOutput());
                $output[] = $process->getOutput();
            }

            return $output;
        } finally {
            foreach ($processes as $process) {
                $process->stop();
            }
            unlink($script);
        }
    }
}
