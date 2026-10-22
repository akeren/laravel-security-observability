<?php

declare(strict_types=1);

namespace Kater\SecurityObservability\Http\Middleware;

use Closure;
use Illuminate\Contracts\Config\Repository;
use Illuminate\Http\Request;
use Kater\SecurityObservability\Context\CorrelationContext;
use Kater\SecurityObservability\Contracts\EventRecorder;
use Kater\SecurityObservability\Events\OperationalEvent;
use Kater\SecurityObservability\TelemetryState;
use Symfony\Component\HttpFoundation\Response;
use Throwable;

final class LogIncomingRequest
{
    public function __construct(private CorrelationContext $context, private EventRecorder $recorder,
        private Repository $config, private TelemetryState $state) {}

    public function handle(Request $request, Closure $next): Response
    {
        if (! $this->config->get('security-observability.enabled') || $this->state->suppressed()) {
            return $next($request);
        }
        $this->context->start($this->config->get('security-observability.http.accept_correlation') ? $request->header('X-Correlation-ID') : null);
        $start = hrtime(true);
        $response = null;
        $exception = null;
        try {
            $response = $next($request);
            foreach ($this->context->snapshot() as $key => $value) {
                if ($key === 'request_id') {
                    $response->headers->set('X-Request-ID', $value);
                }
                if ($key === 'correlation_id') {
                    $response->headers->set('X-Correlation-ID', $value);
                }
            }

            return $response;
        } catch (Throwable $error) {
            $exception = $error;
            throw $error;
        } finally {
            try {
                $route = $request->route();
                $routeData = is_object($route) ? ['route' => $route->uri(), 'route_name' => $route->getName()] : ['route' => null, 'route_name' => null];
                $status = $response?->getStatusCode();
                $failed = $exception !== null || ($status !== null && $status >= 400);
                $this->recorder->record(new OperationalEvent($exception ? 'http.request.failed' : 'http.request.completed', [
                    'http' => ['method' => $request->method(), ...$routeData, 'status' => $status,
                        'duration_ms' => round((hrtime(true) - $start) / 1e6, 3)],
                    'network' => ['client_ip' => $request->ip()],
                    'exception_type' => $exception ? $exception::class : null,
                ], $failed ? 'failure' : 'success', $failed ? 'error' : 'informational'));
            } catch (Throwable) {
                $this->state->failures++;
            } finally {
                $this->context->clear();
            }
        }
    }
}
