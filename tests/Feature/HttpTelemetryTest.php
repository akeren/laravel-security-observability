<?php

declare(strict_types=1);

namespace Kater\SecurityObservability\Tests\Feature;

use Illuminate\Http\Client\ConnectionException;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Route;
use Kater\SecurityObservability\Context\CorrelationContext;
use Kater\SecurityObservability\Contracts\Event;
use Kater\SecurityObservability\Contracts\EventRecorder;
use Kater\SecurityObservability\Http\Middleware\LogIncomingRequest;
use Kater\SecurityObservability\Tests\TelemetryTestCase;
use RuntimeException;

final class HttpTelemetryTest extends TelemetryTestCase
{
    public function test_requests_use_route_templates_exclude_payloads_and_clear_context(): void
    {
        Route::post('/items/{item}', fn () => response()->json(['password' => 'synthetic-response']))->middleware(LogIncomingRequest::class)->name('items.store');
        $first = $this->withHeaders(['X-Correlation-ID' => 'untrusted', 'X-Request-ID' => 'untrusted', 'X-Forwarded-For' => '203.0.113.42', 'Authorization' => 'Bearer synthetic-secret'])
            ->postJson('/items/synthetic-path-secret?token=synthetic-query', ['password' => 'synthetic-body']);
        $first->assertOk();
        self::assertNotSame('untrusted', $first->headers->get('X-Request-ID'));
        self::assertNotSame('untrusted', $first->headers->get('X-Correlation-ID'));
        self::assertSame('items/{item}', $this->sink->events[0]['attributes']['http']['route']);
        self::assertNotSame('203.0.113.42', $this->sink->events[0]['attributes']['network']['client_ip']);
        foreach (['synthetic-secret', 'synthetic-path-secret', 'synthetic-query', 'synthetic-body', 'synthetic-response'] as $secret) {
            self::assertStringNotContainsString($secret, json_encode($this->sink->events));
        }
        self::assertSame([], $this->app->make(CorrelationContext::class)->snapshot());
        $second = $this->postJson('/items/next');
        self::assertNotSame($first->headers->get('X-Correlation-ID'), $second->headers->get('X-Correlation-ID'));
    }

    public function test_upstream_ids_require_opt_in_and_validation(): void
    {
        config(['security-observability.http.accept_correlation' => true]);
        Route::get('/ok', fn () => 'ok')->middleware(LogIncomingRequest::class);
        self::assertSame('synthetic-flow', $this->withHeader('X-Correlation-ID', 'synthetic-flow')->get('/ok')->headers->get('X-Correlation-ID'));
        foreach ([str_repeat('x', 129), "bad\nvalue", ' spaces ', 'bad/identifier'] as $bad) {
            self::assertNull(CorrelationContext::validId($bad));
        }
        self::assertNotSame('bad/identifier', $this->withHeader('X-Correlation-ID', 'bad/identifier')->get('/ok')->headers->get('X-Correlation-ID'));
    }

    public function test_original_exception_survives_a_throwing_recorder_and_context_is_cleared(): void
    {
        $this->app->bind(EventRecorder::class, fn () => new class implements EventRecorder
        {
            public function record(Event $event): void
            {
                throw new RuntimeException('telemetry failure');
            }
        });
        Route::get('/failure', fn () => throw new RuntimeException('original failure'))->middleware(LogIncomingRequest::class);
        try {
            $this->withoutExceptionHandling()->get('/failure');
            self::fail('Expected exception');
        } catch (RuntimeException $error) {
            self::assertSame('original failure', $error->getMessage());
        }
        self::assertSame([], $this->app->make(CorrelationContext::class)->snapshot());
    }

    public function test_outbound_http_propagates_only_to_allowed_origins_and_logs_no_secrets(): void
    {
        config(['security-observability.http.propagation_origins' => ['https://provider.test']]);
        $this->app->make(CorrelationContext::class)->start('synthetic-flow', 'synthetic-request');
        Http::fake(['*' => Http::response(['secret' => 'synthetic-response'])]);
        Http::withToken('synthetic-token')->post('https://provider.test/path-secret?token=query-secret', ['password' => 'body-secret']);
        Http::get('https://other.test');
        Http::assertSent(fn ($request) => $request->url() === 'https://other.test' && ! $request->hasHeader('X-Correlation-ID'));
        Http::assertSent(fn ($request) => str_contains($request->url(), 'provider.test') && $request->hasHeader('X-Correlation-ID', 'synthetic-flow'));
        self::assertCount(2, $this->sink->events);
        self::assertSame('synthetic-flow', $this->sink->events[0]['correlation_id']);
        foreach (['synthetic-token', 'path-secret', 'query-secret', 'body-secret', 'synthetic-response'] as $secret) {
            self::assertStringNotContainsString($secret, json_encode($this->sink->events));
        }
    }

    public function test_outbound_connection_failure_is_rethrown_and_exporter_requests_are_excluded(): void
    {
        Http::fake(['*' => Http::failedConnection('synthetic-secret')]);
        try {
            Http::get('https://provider.test');
            self::fail('Expected exception');
        } catch (ConnectionException) {
        }
        self::assertSame('external_http.failed', $this->sink->events[0]['name']);
        self::assertStringNotContainsString('synthetic-secret', json_encode($this->sink->events));
        try {
            Http::withOptions(['security_observability_skip' => true])->get('https://provider.test');
        } catch (ConnectionException) {
        }
        self::assertCount(1, $this->sink->events);
    }
}
