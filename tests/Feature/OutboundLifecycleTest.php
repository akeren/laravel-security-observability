<?php

declare(strict_types=1);

namespace Kater\SecurityObservability\Tests\Feature;

use GuzzleHttp\Client;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Middleware;
use GuzzleHttp\Promise\Promise;
use GuzzleHttp\Psr7\Request;
use GuzzleHttp\Psr7\Response;
use Kater\SecurityObservability\Context\CorrelationContext;
use Kater\SecurityObservability\Contracts\ContextResolver;
use Kater\SecurityObservability\Http\OutboundTelemetry;
use Kater\SecurityObservability\Tests\TelemetryTestCase;

final class OutboundLifecycleTest extends TelemetryTestCase
{
    public function test_redirect_to_another_origin_does_not_leak_correlation(): void
    {
        config(['security-observability.http.propagation_origins' => ['https://allowed.test']]);
        $this->app->make(CorrelationContext::class)->start('workflow', 'request');
        $stack = HandlerStack::create(new MockHandler([new Response(302, ['Location' => 'https://other.test']), new Response(200)]));
        $stack->push($this->app->make(OutboundTelemetry::class)->middleware());
        $history = [];
        $stack->push(Middleware::history($history));
        (new Client(['handler' => $stack]))->get('https://allowed.test');
        self::assertSame('workflow', $history[0]['request']->getHeaderLine('X-Correlation-ID'));
        self::assertFalse($history[1]['request']->hasHeader('X-Correlation-ID'));
        self::assertCount(2, $this->sink->events);
    }

    public function test_delayed_completion_uses_captured_context_and_restores_current_context(): void
    {
        $context = $this->app->make(CorrelationContext::class);
        $context->start('first-workflow', 'first-request');
        $pending = new Promise;
        $handler = ($this->app->make(OutboundTelemetry::class)->middleware())(fn () => $pending);
        $result = $handler(new Request('GET', 'https://provider.test'), []);
        $context->start('second-workflow', 'second-request');
        $pending->resolve(new Response(200));
        $result->wait();
        self::assertSame('first-workflow', $this->sink->events[0]['correlation_id']);
        self::assertSame('second-workflow', $context->snapshot()['correlation_id']);
    }

    public function test_excluded_redirect_origins_do_not_receive_inherited_correlation(): void
    {
        config(['security-observability.http.propagation_origins' => ['https://allowed.test'], 'security-observability.http.excluded_origins' => ['https://collector.test']]);
        $this->app->make(CorrelationContext::class)->start('workflow', 'request');
        $stack = HandlerStack::create(new MockHandler([new Response(302, ['Location' => 'https://collector.test']), new Response(200)]));
        $stack->push($this->app->make(OutboundTelemetry::class)->middleware());
        $history = [];
        $stack->push(Middleware::history($history));
        (new Client(['handler' => $stack]))->get('https://allowed.test');
        self::assertFalse($history[1]['request']->hasHeader('X-Correlation-ID'));
        self::assertCount(1, $this->sink->events);
    }

    public function test_delayed_completion_retains_originating_tenant_and_actor(): void
    {
        $resolver = new class implements ContextResolver
        {
            public string $tenant = 'first-tenant';

            public function resolve(): array
            {
                return ['tenant' => ['id' => $this->tenant], 'actor' => ['id' => $this->tenant.'-actor']];
            }
        };
        $this->app->instance(ContextResolver::class, $resolver);
        $pending = new Promise;
        $handler = ($this->app->make(OutboundTelemetry::class)->middleware())(fn () => $pending);
        $result = $handler(new Request('GET', 'https://provider.test'), []);
        $resolver->tenant = 'second-tenant';
        $pending->resolve(new Response(200));
        $result->wait();
        self::assertSame('first-tenant', $this->sink->events[0]['tenant']['id']);
        self::assertSame('first-tenant-actor', $this->sink->events[0]['actor']['id']);
    }
}
