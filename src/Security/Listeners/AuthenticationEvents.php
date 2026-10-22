<?php

declare(strict_types=1);

namespace Kater\SecurityObservability\Security\Listeners;

use Illuminate\Auth\Events\Failed;
use Illuminate\Auth\Events\Lockout;
use Illuminate\Auth\Events\Login;
use Illuminate\Auth\Events\Logout;
use Illuminate\Auth\Events\PasswordReset;
use Illuminate\Container\Container;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Config\Repository;
use Illuminate\Contracts\Events\Dispatcher;
use Kater\SecurityObservability\Contracts\AuthenticationIdentityResolver;
use Kater\SecurityObservability\Contracts\ContextResolver;
use Kater\SecurityObservability\Contracts\EventRecorder;
use Kater\SecurityObservability\Delivery\PersistenceFailed;
use Kater\SecurityObservability\Events\Actor;
use Kater\SecurityObservability\Events\ContextualEvent;
use Kater\SecurityObservability\Events\Outcome;
use Kater\SecurityObservability\Events\SecurityEvent;
use Kater\SecurityObservability\Events\Severity;
use Kater\SecurityObservability\Events\Target;
use Kater\SecurityObservability\TelemetryState;
use Throwable;

final class AuthenticationEvents
{
    private bool $registered = false;

    public function __construct(private Container $app, private Repository $config, private TelemetryState $state) {}

    public function register(Dispatcher $events): void
    {
        if ($this->registered) {
            return;
        }
        $this->registered = true;
        foreach ([Login::class, Failed::class, Logout::class, Lockout::class, PasswordReset::class] as $event) {
            $events->listen($event, $this->handle(...));
        }
    }

    public function handle(Login|Failed|Logout|Lockout|PasswordReset $event): void
    {
        if (! $this->config->get('security-observability.enabled')
            || ! $this->config->get('security-observability.security.enabled')
            || ! $this->config->get('security-observability.security.authentication.enabled')
            || $this->state->suppressed()) {
            return;
        }
        $guard = $event->guard ?? null;
        $guards = $this->config->get('security-observability.security.authentication.guards');
        if (($guard !== null && is_array($guards) && ! in_array($guard, $guards, true))
            || ($guard === null && ! $this->config->get('security-observability.security.authentication.include_guardless'))) {
            return;
        }

        $this->state->enter();
        try {
            $subject = $this->subject($event->user ?? null);
            [$name, $action, $outcome, $severity] = match (true) {
                $event instanceof Login => ['identity.authentication.succeeded', 'authenticate', Outcome::Success, Severity::Informational],
                $event instanceof Failed => ['identity.authentication.failed', 'authenticate', Outcome::Failure, Severity::Warning],
                $event instanceof Logout => ['identity.session.ended', 'logout', Outcome::Success, Severity::Informational],
                $event instanceof Lockout => ['identity.authentication.locked_out', 'authenticate', Outcome::Failure, Severity::Warning],
                $event instanceof PasswordReset => ['identity.password.reset', 'reset', Outcome::Success, Severity::Informational],
            };
            // Failed.user identifies an attempted account, not a verified actor.
            // PasswordReset supplies the affected user but does not identify the initiator.
            $actor = $event instanceof Login || $event instanceof Logout ? $subject : null;
            $target = $subject !== null && ($event instanceof Failed || $event instanceof PasswordReset)
                ? new Target($subject->type, $subject->id) : null;
            $attributes = $guard !== null ? ['guard' => $guard] : [];
            if ($event instanceof Lockout) {
                $attributes['network'] = ['client_ip' => $event->request->ip()];
            }
            // Credentials, remember tokens, request data, and full models are never read.
            $context = array_intersect_key($this->app->make(ContextResolver::class)->resolve(), ['tenant' => true]);
            $security = new SecurityEvent($name, $action, $outcome, $severity, $actor, $target, attributes: $attributes);
            $captured = new ContextualEvent($security, $context);
        } catch (Throwable) {
            $this->state->failures++;

            return;
        } finally {
            $this->state->leave();
        }
        try {
            $this->app->make(EventRecorder::class)->record($captured);
        } catch (PersistenceFailed $error) {
            throw $error;
        } catch (Throwable) {
            $this->state->failures++;
        }
    }

    private function subject(mixed $user): ?Actor
    {
        if (! $user instanceof Authenticatable) {
            return null;
        }
        try {
            return $this->app->make(AuthenticationIdentityResolver::class)->resolve($user);
        } catch (Throwable) {
            $this->state->failures++;

            return null;
        }
    }
}
