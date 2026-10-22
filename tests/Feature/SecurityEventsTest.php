<?php

declare(strict_types=1);

namespace Kater\SecurityObservability\Tests\Feature;

use Kater\SecurityObservability\Context\CorrelationContext;
use Kater\SecurityObservability\Contracts\ContextResolver;
use Kater\SecurityObservability\Contracts\EventRecorder;
use Kater\SecurityObservability\Contracts\EventSink;
use Kater\SecurityObservability\Events\Actor;
use Kater\SecurityObservability\Events\OperationalEvent;
use Kater\SecurityObservability\Events\Outcome;
use Kater\SecurityObservability\Events\SecurityEvent;
use Kater\SecurityObservability\Events\Severity;
use Kater\SecurityObservability\Events\Target;
use Kater\SecurityObservability\Events\Tenant;
use Kater\SecurityObservability\Export\Json\JsonEventSink;
use Kater\SecurityObservability\Security\SecurityAction;
use Kater\SecurityObservability\Security\SecurityEvents;
use Kater\SecurityObservability\TelemetryState;
use Kater\SecurityObservability\Tests\TelemetryTestCase;

final class SecurityEventsTest extends TelemetryTestCase
{
    public function test_typed_security_envelope_cannot_be_overwritten_by_attributes(): void
    {
        $this->app->make(CorrelationContext::class)->start('workflow', 'request');
        $this->app->bind(ContextResolver::class, fn () => new class implements ContextResolver
        {
            public function resolve(): array
            {
                return ['actor' => ['type' => 'user', 'id' => 'ambient'], 'tenant' => ['type' => 'tenant', 'id' => 'ambient']];
            }
        });
        $event = new SecurityEvent('identity.credential.rotated', 'rotate', Outcome::Success, Severity::Warning,
            new Actor('user', 0), new Target('api_credential', 'key-id'), new Tenant('organization', 'tenant-a'),
            ['event_id' => 'spoofed', 'kind' => 'operational', 'actor' => ['id' => 'spoofed'], 'token' => 'synthetic-secret', 'correlation_id' => 'spoofed']);
        $recorder = $this->app->make(EventRecorder::class);
        $recorder->record($event);
        $recorder->record($event);
        $result = $this->sink->events[0];
        self::assertSame('0.2', $result['schema_version']);
        self::assertSame('security', $result['kind']);
        self::assertSame('rotate', $result['action']);
        self::assertSame('success', $result['outcome']);
        self::assertSame('warning', $result['severity']);
        self::assertSame(['type' => 'user', 'id' => 0], $result['actor']);
        self::assertSame(['type' => 'api_credential', 'id' => 'key-id'], $result['target']);
        self::assertSame(['type' => 'organization', 'id' => 'tenant-a'], $result['tenant']);
        self::assertSame('workflow', $result['correlation_id']);
        self::assertSame($event->id(), $result['event_id']);
        self::assertSame($result['event_id'], $this->sink->events[1]['event_id']);
        self::assertSame($result['occurred_at'], $this->sink->events[1]['occurred_at']);
        self::assertStringNotContainsString('synthetic-secret', json_encode($result));
    }

    public function test_host_adapter_correlates_privilege_change_and_sensitive_export(): void
    {
        $this->app->make(CorrelationContext::class)->start('workflow', 'request');
        $adapter = $this->app->make(SecurityEvents::class);
        $actor = new Actor('operator', 'operator-1');
        $tenant = new Tenant('tenant', 'tenant-1');
        $adapter->emit(SecurityAction::PrivilegeChanged, Outcome::Success, $actor, new Target('role', 'reviewer'), $tenant, ['reason' => 'synthetic change']);
        $adapter->emit(SecurityAction::SensitiveExport, Outcome::Failure, $actor, new Target('report', 'report-1'), $tenant, ['api_key' => 'synthetic-secret'], Severity::Critical);
        $adapter->record(new SecurityEvent('domain.policy.observed', 'observe', attributes: ['password' => 'synthetic-secret']));
        self::assertSame(['identity.privilege.changed', 'data.sensitive.exported', 'domain.policy.observed'], array_column($this->sink->events, 'name'));
        self::assertSame('change', $this->sink->events[0]['action']);
        self::assertSame('export', $this->sink->events[1]['action']);
        self::assertSame('failure', $this->sink->events[1]['outcome']);
        self::assertSame('critical', $this->sink->events[1]['severity']);
        self::assertSame('unknown', $this->sink->events[2]['outcome']);
        foreach ($this->sink->events as $event) {
            self::assertSame('workflow', $event['correlation_id']);
        }
        self::assertStringNotContainsString('synthetic-secret', json_encode($this->sink->events));
    }

    public function test_security_recording_can_be_disabled_without_disabling_operational_events(): void
    {
        config(['security-observability.security.enabled' => false]);
        $recorder = $this->app->make(EventRecorder::class);
        $recorder->record(new SecurityEvent('security.disabled', 'observe'));
        $recorder->record(new OperationalEvent('operation.enabled'));
        self::assertSame(['operation.enabled'], array_column($this->sink->events, 'name'));
        self::assertFalse($this->app->make(TelemetryState::class)->suppressed());
    }

    public function test_security_event_without_explicit_identity_uses_resolver_and_does_not_leak_tenants(): void
    {
        $resolver = new class implements ContextResolver
        {
            public string $tenant = 'tenant-a';

            public function resolve(): array
            {
                return ['tenant' => ['type' => 'tenant', 'id' => $this->tenant], 'actor' => ['type' => 'user', 'id' => $this->tenant.'-user']];
            }
        };
        $this->app->instance(ContextResolver::class, $resolver);
        $adapter = $this->app->make(SecurityEvents::class);
        $adapter->emit(SecurityAction::MfaFailed, Outcome::Failure, attributes: ['otp' => 'synthetic-otp']);
        $resolver->tenant = 'tenant-b';
        $adapter->emit(SecurityAction::CredentialRevoked, Outcome::Success, target: new Target('credential', 'credential-b'));
        self::assertSame('tenant-a', $this->sink->events[0]['tenant']['id']);
        self::assertSame('tenant-b', $this->sink->events[1]['tenant']['id']);
        self::assertSame('tenant-b-user', $this->sink->events[1]['actor']['id']);
        self::assertSame('[REDACTED]', $this->sink->events[0]['attributes']['otp']);
    }

    public function test_critical_security_event_reaches_actual_json_channel_and_privacy_still_applies(): void
    {
        $path = tempnam(sys_get_temp_dir(), 'security-json-');
        config(['logging.channels.security-observability.with.stream' => $path, 'logging.channels.security-observability.level' => 'critical']);
        $this->app->bind(EventSink::class, JsonEventSink::class);
        try {
            $this->app->make(SecurityEvents::class)->emit(SecurityAction::AuthorizationDenied, Outcome::Failure,
                attributes: ['password' => 'synthetic-secret'], severity: Severity::Critical);
            $lines = file($path, FILE_IGNORE_NEW_LINES);
            self::assertCount(1, $lines);
            $result = json_decode($lines[0], true, flags: JSON_THROW_ON_ERROR);
            self::assertSame('security', $result['kind']);
            self::assertSame('critical', $result['severity']);
            self::assertSame('[REDACTED]', $result['attributes']['password']);
        } finally {
            $this->app['log']->forgetChannel('security-observability');
            unlink($path);
        }
    }

    public function test_attribute_limits_preserve_typed_identity_but_explicit_identity_redaction_applies(): void
    {
        config(['security-observability.privacy.max_items' => 1, 'security-observability.privacy.max_nodes' => 1, 'security-observability.privacy.max_string_bytes' => 16]);
        $actor = new Actor('service', str_repeat('a', 256));
        $event = new SecurityEvent('identity.checked', 'check', actor: $actor, attributes: ['detail' => str_repeat('x', 200)]);
        $this->app->make(EventRecorder::class)->record($event);
        self::assertSame($actor->toArray(), $this->sink->events[0]['actor']);
        self::assertSame(16, strlen($this->sink->events[0]['attributes']['detail']));
        config(['security-observability.privacy.redact_paths' => ['/actor/id']]);
        $this->app->make(EventRecorder::class)->record($event);
        self::assertSame('[REDACTED]', $this->sink->events[1]['actor']['id']);
    }
}
