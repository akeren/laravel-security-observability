<?php

declare(strict_types=1);

namespace Kater\SecurityObservability;

use Illuminate\Console\Events\CommandFinished;
use Illuminate\Console\Events\CommandStarting;
use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Http\Client\Factory;
use Illuminate\Support\ServiceProvider;
use Kater\SecurityObservability\Console\DeliveryCommand;
use Kater\SecurityObservability\Context\CommandContext;
use Kater\SecurityObservability\Context\CorrelationContext;
use Kater\SecurityObservability\Context\NullContextResolver;
use Kater\SecurityObservability\Contracts\AuthenticationIdentityResolver;
use Kater\SecurityObservability\Contracts\ContextResolver;
use Kater\SecurityObservability\Contracts\DeliveryStore;
use Kater\SecurityObservability\Contracts\DeliveryTransport;
use Kater\SecurityObservability\Contracts\EventMapper;
use Kater\SecurityObservability\Contracts\EventRecorder;
use Kater\SecurityObservability\Contracts\EventSink;
use Kater\SecurityObservability\Contracts\Redactor;
use Kater\SecurityObservability\Contracts\RetryPolicy;
use Kater\SecurityObservability\Delivery\DeliveryDriver;
use Kater\SecurityObservability\Delivery\ElasticsearchTransport;
use Kater\SecurityObservability\Delivery\JsonHttpTransport;
use Kater\SecurityObservability\Delivery\Outbox;
use Kater\SecurityObservability\Export\Ecs\EcsMapper;
use Kater\SecurityObservability\Export\Json\EventJsonFormatter;
use Kater\SecurityObservability\Export\Json\JsonEventSink;
use Kater\SecurityObservability\Export\Json\NativeMapper;
use Kater\SecurityObservability\Http\OutboundTelemetry;
use Kater\SecurityObservability\Privacy\PrivacyPipeline;
use Kater\SecurityObservability\Queue\QueueTelemetry;
use Kater\SecurityObservability\Security\AuthenticationIdentity;
use Kater\SecurityObservability\Security\Listeners\AuthenticationEvents;
use Monolog\Handler\StreamHandler;

final class SecurityObservabilityServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->mergeConfigFrom(__DIR__.'/../config/security-observability.php', 'security-observability');
        DeliveryDriver::configured($this->app['config']);
        $this->app->bindIf(DeliveryStore::class, Outbox::class);
        $this->app->bindIf(RetryPolicy::class, Delivery\RetryPolicy::class);
        $this->app->bindIf(DeliveryTransport::class, function ($app) {
            return $app->make(match ($app['config']->get('security-observability.delivery.transport', 'http')) {
                'http' => JsonHttpTransport::class,
                'elasticsearch' => ElasticsearchTransport::class,
                default => throw new \LogicException('Unsupported telemetry transport.'),
            });
        });
        $this->app->scoped(CorrelationContext::class);
        $this->app->singleton(TelemetryState::class);
        $this->app->bindIf(ContextResolver::class, NullContextResolver::class);
        $this->app->bindIf(Redactor::class, PrivacyPipeline::class);
        $this->app->bindIf(EventSink::class, fn ($app) => $app->make(
            DeliveryDriver::configured($app['config']) === DeliveryDriver::Outbox
                ? Outbox::class : JsonEventSink::class));
        $this->app->bindIf(EventMapper::class, function ($app) {
            return match ($app['config']->get('security-observability.format', 'native')) {
                'native' => new NativeMapper,
                'ecs' => new EcsMapper,
                default => throw new \LogicException('Unsupported telemetry format.'),
            };
        });
        $this->app->bindIf(EventRecorder::class, Recorder::class);
        $this->app->singleton(QueueTelemetry::class);
        $this->app->singleton(CommandContext::class);
        $this->app->bindIf(AuthenticationIdentityResolver::class, AuthenticationIdentity::class);
        $this->app->singleton(AuthenticationEvents::class);
    }

    public function boot(Dispatcher $events): void
    {
        $config = $this->app['config'];
        if ($config->get('logging.channels.security-observability') === null) {
            $config->set('logging.channels.security-observability', [
                'driver' => 'monolog', 'handler' => StreamHandler::class,
                'with' => ['stream' => $config->get('security-observability.output')],
                'formatter' => EventJsonFormatter::class,
            ]);
        }
        $this->app->make(QueueTelemetry::class)->register($events);
        $this->app->make(AuthenticationEvents::class)->register($events);
        $this->callAfterResolving(Factory::class, function (Factory $factory): void {
            $factory->globalMiddleware($this->app->make(OutboundTelemetry::class)->middleware());
        });
        $events->listen(CommandStarting::class, fn () => $this->app->make(CommandContext::class)->starting());
        $events->listen(CommandFinished::class, fn () => $this->app->make(CommandContext::class)->finished());
        if ($this->app->runningInConsole()) {
            $this->commands([DeliveryCommand::class]);
            $this->publishes([__DIR__.'/../database/migrations' => database_path('migrations')], 'security-observability-migrations');
            $this->publishes([__DIR__.'/../config/security-observability.php' => config_path('security-observability.php')], 'security-observability-config');
        }
    }
}
