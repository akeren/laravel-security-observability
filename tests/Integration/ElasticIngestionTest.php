<?php

declare(strict_types=1);

namespace Kater\SecurityObservability\Tests\Integration;

use Illuminate\Http\Client\Factory;
use Illuminate\Http\Client\PendingRequest;
use Kater\SecurityObservability\Contracts\EventRecorder;
use Kater\SecurityObservability\Delivery\Exporter;
use Kater\SecurityObservability\Delivery\Outbox;
use Kater\SecurityObservability\Events\SanitizedEvent;
use Kater\SecurityObservability\Events\SecurityEvent;
use Kater\SecurityObservability\Export\Json\JsonEventSink;
use Kater\SecurityObservability\Tests\Fixtures\SocScenario;
use Kater\SecurityObservability\Tests\TestCase;
use Symfony\Component\Process\Process;

final class ElasticIngestionTest extends TestCase
{
    private function example(): string
    {
        return dirname(__DIR__, 2).'/examples/elastic';
    }

    private function admin(): PendingRequest
    {
        $env = parse_ini_file($this->example().'/.runtime/elastic.env');

        return (new Factory)->withOptions(['verify' => $this->example().'/.runtime/certs/server.crt'])
            ->withBasicAuth('elastic', $env['ELASTIC_PASSWORD'])->timeout(15)->baseUrl('https://localhost:19200');
    }

    protected function defineEnvironment($app): void
    {
        $app['config']->set('database.default', 'testing');
        $app['config']->set('database.connections.testing', ['driver' => 'sqlite', 'database' => ':memory:', 'prefix' => '']);
        foreach (['enabled' => true, 'format' => 'ecs', 'delivery.driver' => 'outbox', 'delivery.transport' => 'elasticsearch',
            'delivery.endpoint' => 'https://localhost:19200/security-observability-direct/_doc',
            'delivery.auth_scheme' => 'ApiKey', 'delivery.ca_bundle' => $this->example().'/.runtime/certs/server.crt'] as $key => $value) {
            $app['config']->set('security-observability.'.$key, $value);
        }
    }

    private function compose(string ...$arguments): void
    {
        $process = new Process(['docker', 'compose', ...$arguments], $this->example());
        $process->setTimeout(240)->mustRun();
    }

    public function test_real_ingestion_investigations_duplicates_collector_and_outage_recovery(): void
    {
        $versions = json_decode(file_get_contents($this->example().'/versions.json'), true);
        self::assertSame($versions['elasticsearch'], $this->admin()->get('/')->throw()->json('version.number'));
        $this->admin()->put('/_index_template/security-observability', json_decode(file_get_contents($this->example().'/index-template.json'), true))->throw();
        $this->admin()->put('/_ingest/pipeline/security-observability-ecs-v1', json_decode(file_get_contents($this->example().'/ingest-pipeline.json'), true))->throw();
        // The runner only addresses the isolated localhost example and its two synthetic test indices.
        foreach (['direct', 'collector'] as $name) {
            $response = $this->admin()->delete('/security-observability-'.$name);
            self::assertContains($response->status(), [200, 404]);
            $this->admin()->put('/security-observability-'.$name, $name === 'collector'
                ? json_decode(file_get_contents($this->example().'/collector-index.json'), true) : [])->throw();
        }
        $key = $this->admin()->post('/_security/api_key', ['name' => 'synthetic-exporter', 'expiration' => '1h',
            'role_descriptors' => ['exporter' => ['indices' => [['names' => ['security-observability-direct'], 'privileges' => ['write']]]]]])->throw()->json();
        config(['security-observability.delivery.token' => $key['encoded']]);
        $log = null;
        try {
            (require dirname(__DIR__, 2).'/database/migrations/2026_10_18_000000_create_security_observability_outbox.php')->up();
            SocScenario::emit($this->app);
            $outbox = $this->app->make(Outbox::class);
            $native = $outbox->rows()->orderBy('created_at')->get();
            self::assertGreaterThanOrEqual(13, $native->count());
            self::assertSame($native->count(), $this->app->make(Exporter::class)->run());
            self::assertSame(0, $outbox->health()['backlog']);
            $this->admin()->send('POST', '/security-observability-direct/_refresh')->throw();
            $this->assertInvestigations('direct', $native->count());
            $first = $native->first();
            $before = $this->admin()->get('/security-observability-direct/_doc/'.$first->event_id)->throw()->json('_source');
            // Simulate an acknowledgment lost after Elasticsearch committed the document.
            $outbox->rows()->where('event_id', $first->event_id)->update(['status' => 'pending', 'next_attempt' => time() - 1]);
            self::assertSame(1, $this->app->make(Exporter::class)->run());
            $after = $this->admin()->get('/security-observability-direct/_doc/'.$first->event_id)->throw()->json('_source');
            self::assertSame($before, $after);
            $this->admin()->send('POST', '/security-observability-direct/_refresh')->throw();
            self::assertSame($native->count(), $this->admin()->get('/security-observability-direct/_count')->throw()->json('count'));

            $log = $this->example().'/.runtime/logs/events-'.bin2hex(random_bytes(4)).'.jsonl';
            config(['logging.channels.security-observability.with.stream' => $log]);
            $sink = $this->app->make(JsonEventSink::class);
            foreach ($native as $row) {
                $sink->write(new SanitizedEvent($row->payload));
                $sink->write(new SanitizedEvent($row->payload));
            }
            $this->app['log']->forgetChannel('security-observability');
            $this->compose('up', '-d', 'filebeat');
            $deadline = time() + 90;
            do {
                $this->admin()->send('POST', '/security-observability-collector/_refresh')->throw();
                $count = $this->admin()->get('/security-observability-collector/_count')->throw()->json('count');
                if ($count === $native->count()) {
                    break;
                }
                usleep(500000);
            } while (time() < $deadline);
            self::assertSame($native->count(), $count, 'Collector must ingest each event ID once.');
            $this->assertInvestigations('collector', $native->count());
            foreach ($native as $row) {
                $collected = $this->admin()->get('/security-observability-collector/_doc/'.$row->event_id)->throw()->json('_source');
                self::assertSame(json_decode($row->payload, true)['occurred_at'], $collected['@timestamp']);
            }

            $this->compose('stop', 'elasticsearch');
            try {
                $this->app->make(EventRecorder::class)->record(new SecurityEvent('security.outage_probe', 'observe'));
                $this->app->make(Exporter::class)->run();
                self::assertSame(1, $outbox->health()['backlog']);
                self::assertSame('connection', $outbox->rows()->where('status', 'pending')->value('failure'));
            } finally {
                $this->compose('up', '-d', '--wait', 'elasticsearch');
            }
            $outbox->rows()->where('status', 'pending')->update(['next_attempt' => time() - 1]);
            self::assertSame(1, $this->app->make(Exporter::class)->run());
            self::assertSame(0, $outbox->health()['backlog']);
            $this->admin()->send('POST', '/security-observability-direct/_refresh')->throw();
            self::assertSame($native->count() + 1, $this->admin()->get('/security-observability-direct/_count')->throw()->json('count'));
        } finally {
            $this->admin()->delete('/_security/api_key', ['ids' => [$key['id']]])->throw();
            $this->compose('stop', 'filebeat');
            if ($log !== null && is_file($log)) {
                unlink($log);
            }
        }
    }

    private function assertInvestigations(string $suffix, int $count): void
    {
        $index = '/security-observability-'.$suffix;
        $queries = json_decode(file_get_contents($this->example().'/queries.json'), true);
        foreach (['authentication_sequence', 'privilege_export', 'credential_reuse'] as $name) {
            $result = $this->admin()->post($index.'/_eql/search', $queries[$name])->throw()->json();
            self::assertCount(1, $result['hits']['sequences'], $name);
            foreach ($result['hits']['sequences'][0]['events'] as $event) {
                self::assertSame('tenant-a', $event['_source']['kater']['tenant']['id']);
                self::assertSame('event', $event['_source']['event']['kind']);
            }
        }
        $result = $this->admin()->post($index.'/_search', $queries['workflow'])->throw()->json();
        self::assertSame($count, $result['hits']['total']['value']);
        $codes = array_map(fn ($hit) => $hit['_source']['event']['code'], $result['hits']['hits']);
        self::assertContains('http.request.completed', $codes);
        self::assertContains('queue.job.processed', $codes);
        self::assertStringNotContainsString('synthetic-secret', json_encode($result));
        foreach ($result['hits']['hits'] as $hit) {
            self::assertSame($hit['_id'], $hit['_source']['event']['id']);
            self::assertSame('9.5.0', $hit['_source']['ecs']['version']);
            self::assertSame(str_repeat('1', 32), $hit['_source']['trace']['id']);
        }
        $mapping = $this->admin()->get($index.'/_mapping')->throw()->json();
        self::assertSame('date_nanos', $mapping['security-observability-'.$suffix]['mappings']['properties']['@timestamp']['type']);
    }
}
