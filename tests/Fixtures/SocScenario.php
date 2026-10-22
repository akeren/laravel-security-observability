<?php

declare(strict_types=1);

namespace Kater\SecurityObservability\Tests\Fixtures;

use Illuminate\Auth\Events\Failed;
use Illuminate\Auth\Events\Login;
use Illuminate\Auth\GenericUser;
use Illuminate\Container\Container;
use Kater\SecurityObservability\Context\CorrelationContext;
use Kater\SecurityObservability\Contracts\ContextResolver;
use Kater\SecurityObservability\Contracts\EventRecorder;
use Kater\SecurityObservability\Events\Actor;
use Kater\SecurityObservability\Events\OperationalEvent;
use Kater\SecurityObservability\Events\Outcome;
use Kater\SecurityObservability\Events\SecurityEvent;
use Kater\SecurityObservability\Events\Target;
use Kater\SecurityObservability\Events\Tenant;

final class SocScenario
{
    public static function emit(Container $app): void
    {
        $app->instance(ContextResolver::class, new class implements ContextResolver
        {
            public function resolve(): array
            {
                return ['tenant' => ['type' => 'tenant', 'id' => 'tenant-a']];
            }
        });
        $context = $app->make(CorrelationContext::class);
        $context->start('workflow-synthetic', 'request-synthetic', ['trace_id' => str_repeat('1', 32), 'span_id' => str_repeat('2', 16)]);
        $user = new GenericUser(['id' => 'pseudo-user-1']);
        $app['events']->dispatch(new Failed('web', $user, ['password' => 'synthetic-secret']));
        usleep(1000);
        $app['events']->dispatch(new Failed('web', $user, ['password' => 'synthetic-secret']));
        usleep(1000);
        $app['events']->dispatch(new Login('web', $user, false));
        $recorder = $app->make(EventRecorder::class);
        $actor = new Actor('user', 'pseudo-user-1');
        $tenant = new Tenant('tenant', 'tenant-a');
        foreach ([['identity.privilege.changed', 'change', new Target('role', 'reviewer')],
            ['data.sensitive.exported', 'export', new Target('report', 'report-1')],
            ['identity.credential.rotated', 'rotate', new Target('credential', 'credential-old')],
            ['identity.authentication.revoked_credential', 'authenticate', new Target('credential', 'credential-old')]] as [$name, $action, $target]) {
            usleep(1000);
            $recorder->record(new SecurityEvent($name, $action, $action === 'authenticate' ? Outcome::Failure : Outcome::Success,
                actor: $actor, target: $target, tenant: $tenant, attributes: ['token' => 'synthetic-secret']));
        }
        $recorder->record(new OperationalEvent('http.request.completed', ['http' => ['method' => 'GET', 'status' => 200, 'route' => 'reports/{report}', 'duration_ms' => 12.125], 'network' => ['client_ip' => '192.0.2.1']], 'success'));
        $app['queue']->connection('sync')->push(new ContextJob);
        // These cannot form a sequence: the matching subject belongs to different tenants.
        foreach (['tenant-b', 'tenant-b', 'tenant-c'] as $i => $tenantId) {
            usleep(1000);
            $recorder->record(new SecurityEvent($i === 2 ? 'identity.authentication.succeeded' : 'identity.authentication.failed', 'authenticate',
                $i === 2 ? Outcome::Success : Outcome::Failure,
                actor: $i === 2 ? $actor : null, target: $i !== 2 ? new Target('user', $actor->id) : null, tenant: new Tenant('tenant', $tenantId)));
        }
    }
}
