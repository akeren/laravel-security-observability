<?php

declare(strict_types=1);

namespace Kater\SecurityObservability\Http;

use GuzzleHttp\Promise\Create;
use Illuminate\Container\Container;
use Illuminate\Contracts\Config\Repository;
use Kater\SecurityObservability\Context\CorrelationContext;
use Kater\SecurityObservability\Contracts\ContextResolver;
use Kater\SecurityObservability\Contracts\EventRecorder;
use Kater\SecurityObservability\Events\ContextualEvent;
use Kater\SecurityObservability\Events\OperationalEvent;
use Kater\SecurityObservability\Privacy\PrivacyPipeline;
use Kater\SecurityObservability\TelemetryState;
use Psr\Http\Message\RequestInterface;
use Throwable;

final class OutboundTelemetry
{
    public function __construct(private Container $app, private Repository $config, private TelemetryState $state) {}

    public function middleware(): callable
    {
        return function (callable $handler): callable {
            return function (RequestInterface $request, array $options) use ($handler) {
                $uri = $request->getUri();
                $origin = strtolower($uri->getScheme().'://'.$uri->getHost()).($uri->getPort() ? ':'.$uri->getPort() : '');
                if (! $this->config->get('security-observability.enabled') || ! $this->config->get('security-observability.http.outbound')) {
                    return $handler($request, $options);
                }
                // Strip before exclusions as redirects may inherit a previously propagated header.
                $request = $request->withoutHeader('X-Correlation-ID');
                if ($this->state->suppressed() || ($options['security_observability_skip'] ?? false)
                    || in_array($origin, $this->config->get('security-observability.http.excluded_origins', []), true)) {
                    return $handler($request, $options);
                }
                $context = $this->app->make(CorrelationContext::class);
                $snapshot = $context->snapshot();
                if (in_array($origin, $this->config->get('security-observability.http.propagation_origins', []), true)
                    && isset($snapshot['correlation_id'])) {
                    $request = $request->withHeader('X-Correlation-ID', $snapshot['correlation_id']);
                }
                $identity = [];
                $this->state->enter();
                try {
                    $resolved = $this->app->make(ContextResolver::class)->resolve();
                    $identity = $this->app->make(PrivacyPipeline::class)->redact(array_intersect_key($resolved, array_flip(['actor', 'tenant', 'target'])));
                } catch (Throwable) {
                    $this->state->failures++;
                } finally {
                    $this->state->leave();
                }
                $start = hrtime(true);
                $emit = function (?int $status, mixed $error = null) use ($snapshot, $start, $request, $origin, $identity): void {
                    try {
                        $context = $this->app->make(CorrelationContext::class);
                        $context->within($snapshot, function () use ($status, $error, $start, $request, $origin, $identity): void {
                            $failed = $error !== null || ($status !== null && $status >= 400);
                            $this->app->make(EventRecorder::class)->record(new ContextualEvent(new OperationalEvent($error ? 'external_http.failed' : 'external_http.completed', [
                                'http' => ['method' => $request->getMethod(), 'origin' => $origin,
                                    'status' => $status, 'duration_ms' => round((hrtime(true) - $start) / 1e6, 3)],
                                'exception_type' => $error instanceof Throwable ? $error::class : null,
                            ], $failed ? 'failure' : 'success', $failed ? 'warning' : 'informational'), $identity));
                        });
                    } catch (Throwable) {
                        $this->state->failures++;
                    }
                };
                try {
                    $promise = $handler($request, $options);
                } catch (Throwable $error) {
                    $emit(null, $error);
                    throw $error;
                }

                return $promise->then(
                    function ($response) use ($emit) {
                        $emit($response->getStatusCode());

                        return $response;
                    },
                    function ($reason) use ($emit) {
                        $emit(null, $reason);

                        return Create::rejectionFor($reason);
                    },
                );
            };
        };
    }
}
