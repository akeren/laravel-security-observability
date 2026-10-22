<?php

declare(strict_types=1);

namespace Kater\SecurityObservability\Tests\Feature;

use Illuminate\Auth\Events\Authenticated;
use Illuminate\Auth\Events\Failed;
use Illuminate\Auth\Events\Lockout;
use Illuminate\Auth\Events\Login;
use Illuminate\Auth\Events\PasswordReset;
use Illuminate\Auth\GenericUser;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Schema;
use Kater\SecurityObservability\Contracts\AuthenticationIdentityResolver;
use Kater\SecurityObservability\Contracts\ContextResolver;
use Kater\SecurityObservability\Contracts\Event;
use Kater\SecurityObservability\Contracts\EventRecorder;
use Kater\SecurityObservability\Events\Actor;
use Kater\SecurityObservability\Security\Listeners\AuthenticationEvents;
use Kater\SecurityObservability\TelemetryState;
use Kater\SecurityObservability\Tests\TelemetryTestCase;
use RuntimeException;

final class AuthenticationTelemetryTest extends TelemetryTestCase
{
    public function test_real_session_guard_flows_emit_only_expected_events_without_credentials(): void
    {
        config(['auth.providers.users.driver' => 'database', 'auth.providers.users.table' => 'users']);
        Schema::create('users', function (Blueprint $table): void {
            $table->id();
            $table->string('email');
            $table->string('password');
            $table->rememberToken();
        });
        DB::table('users')->insert(['id' => 12, 'email' => 'synthetic@example.test', 'password' => Hash::make('synthetic-password')]);
        $guard = Auth::guard('web');
        self::assertFalse($guard->attempt(['email' => 'unknown@example.test', 'password' => 'synthetic-password']));
        self::assertFalse($guard->attempt(['email' => 'synthetic@example.test', 'password' => 'wrong-secret']));
        self::assertTrue($guard->attempt(['email' => 'synthetic@example.test', 'password' => 'synthetic-password']));
        $guard->logout();
        self::assertSame(['identity.authentication.failed', 'identity.authentication.failed', 'identity.authentication.succeeded', 'identity.session.ended'], array_column($this->sink->events, 'name'));
        self::assertArrayNotHasKey('actor', $this->sink->events[0]);
        self::assertArrayNotHasKey('target', $this->sink->events[0]);
        self::assertArrayNotHasKey('actor', $this->sink->events[1]);
        self::assertSame(12, $this->sink->events[1]['target']['id']);
        self::assertSame(12, $this->sink->events[2]['actor']['id']);
        self::assertSame('web', $this->sink->events[2]['attributes']['guard']);
        $json = json_encode($this->sink->events);
        foreach (['synthetic-password', 'wrong-secret', 'synthetic@example.test', 'unknown@example.test'] as $secret) {
            self::assertStringNotContainsString($secret, $json);
        }
    }

    public function test_unknown_actors_and_guardless_events_do_not_inherit_an_ambient_user(): void
    {
        $this->app->bind(ContextResolver::class, fn () => new class implements ContextResolver
        {
            public function resolve(): array
            {
                return ['actor' => ['id' => 'ambient-admin'], 'target' => ['id' => 'ambient-target'], 'tenant' => ['type' => 'tenant', 'id' => 'tenant-a']];
            }
        });
        $user = new GenericUser(['id' => 'user-1', 'password' => 'synthetic-secret']);
        $request = Request::create('/login?token=synthetic-query', 'POST', ['password' => 'synthetic-secret'], server: ['REMOTE_ADDR' => '192.0.2.1', 'HTTP_AUTHORIZATION' => 'Bearer synthetic-token']);
        foreach ([new Failed('api', null, ['password' => 'synthetic-secret']), new Lockout($request), new PasswordReset($user)] as $event) {
            $this->app['events']->dispatch($event);
        }
        foreach ($this->sink->events as $event) {
            self::assertArrayNotHasKey('actor', $event);
            self::assertSame('tenant-a', $event['tenant']['id']);
        }
        self::assertSame('identity.authentication.locked_out', $this->sink->events[1]['name']);
        self::assertSame('192.0.2.1', $this->sink->events[1]['attributes']['network']['client_ip']);
        self::assertSame('identity.password.reset', $this->sink->events[2]['name']);
        self::assertSame('user-1', $this->sink->events[2]['target']['id']);
        self::assertStringNotContainsString('synthetic-', json_encode($this->sink->events));
        self::assertStringNotContainsString('ambient-', json_encode($this->sink->events));
    }

    public function test_guard_allowlist_and_guardless_switch_are_independent(): void
    {
        config(['security-observability.security.authentication.guards' => ['web'], 'security-observability.security.authentication.include_guardless' => false]);
        $user = new GenericUser(['id' => 1]);
        foreach ([new Login('api', $user, false), new Login('web', $user, false), new PasswordReset($user), new Lockout(Request::create('/login'))] as $event) {
            $this->app['events']->dispatch($event);
        }
        self::assertCount(1, $this->sink->events);
        config(['security-observability.security.authentication.include_guardless' => true]);
        $this->app['events']->dispatch(new PasswordReset($user));
        self::assertCount(2, $this->sink->events);
    }

    public function test_disabled_listeners_never_resolve_user_identity(): void
    {
        $this->app->bind(AuthenticationIdentityResolver::class, fn () => throw new RuntimeException('Must not resolve'));
        config(['security-observability.security.authentication.enabled' => false]);
        $this->app['events']->dispatch(new Login('web', new GenericUser(['id' => 1]), false));
        self::assertSame([], $this->sink->events);
        self::assertSame(0, $this->app->make(TelemetryState::class)->failures);
    }

    public function test_registration_is_idempotent_and_authenticated_refresh_does_not_duplicate_login(): void
    {
        $listener = $this->app->make(AuthenticationEvents::class);
        $listener->register($this->app['events']);
        $listener->register($this->app['events']);
        $user = new GenericUser(['id' => 1]);
        $this->app['events']->dispatch(new Login('web', $user, false));
        $this->app['events']->dispatch(new Authenticated('web', $user));
        self::assertCount(1, $this->sink->events);
    }

    public function test_custom_identity_mapping_is_supported_without_serializing_models(): void
    {
        $this->app->bind(AuthenticationIdentityResolver::class, fn () => new class implements AuthenticationIdentityResolver
        {
            public function resolve(Authenticatable $user): ?Actor
            {
                return new Actor('principal', 'pseudonymous-id');
            }
        });
        $this->app['events']->dispatch(new Login('api', new GenericUser(['id' => 'raw-id', 'token' => 'synthetic-secret']), false));
        self::assertSame(['type' => 'principal', 'id' => 'pseudonymous-id'], $this->sink->events[0]['actor']);
        self::assertStringNotContainsString('raw-id', json_encode($this->sink->events));
    }

    public function test_recorder_failure_never_changes_authentication_event_dispatch(): void
    {
        $this->app->bind(EventRecorder::class, fn () => new class implements EventRecorder
        {
            public function record(Event $event): void
            {
                throw new RuntimeException('sink secret');
            }
        });
        $this->app['events']->dispatch(new Login('web', new GenericUser(['id' => 1]), false));
        self::assertSame(1, $this->app->make(TelemetryState::class)->failures);
        self::assertFalse($this->app->make(TelemetryState::class)->suppressed());
    }

    public function test_identity_failure_emits_an_unknown_actor_and_recursive_auth_events_are_suppressed(): void
    {
        $this->app->bind(AuthenticationIdentityResolver::class, fn () => new class implements AuthenticationIdentityResolver
        {
            public function resolve(Authenticatable $user): ?Actor
            {
                app('events')->dispatch(new Login('web', $user, false));
                throw new RuntimeException('identity secret');
            }
        });
        $this->app['events']->dispatch(new Login('web', new GenericUser(['id' => 1]), false));
        self::assertCount(1, $this->sink->events);
        self::assertArrayNotHasKey('actor', $this->sink->events[0]);
        self::assertSame(1, $this->app->make(TelemetryState::class)->failures);
    }
}
