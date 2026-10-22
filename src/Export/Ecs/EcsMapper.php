<?php

declare(strict_types=1);

namespace Kater\SecurityObservability\Export\Ecs;

use DateTimeImmutable;
use Kater\SecurityObservability\Contracts\EcsEventMapper;
use Kater\SecurityObservability\Events\SanitizedEvent;
use Kater\SecurityObservability\Events\Severity;

/** ECS subset mapping. Package-specific fields stay under kater; attributes cannot override ECS. */
final class EcsMapper implements EcsEventMapper
{
    public const ECS_VERSION = '9.5.0';

    public const MAPPER_VERSION = '1.0.0';

    public function map(SanitizedEvent $event): array
    {
        $raw = $event->toArray();
        if (($raw['schema_version'] ?? null) !== '0.2'
            || ! in_array($raw['kind'] ?? null, ['operational', 'security'], true)
            || ! in_array($raw['outcome'] ?? null, ['success', 'failure', 'unknown'], true)
            || ! is_string($raw['event_id'] ?? null) || ! is_string($raw['name'] ?? null)
            || ! is_string($raw['action'] ?? null)
            || ! is_string($raw['severity'] ?? null) || Severity::tryFrom($raw['severity']) === null) {
            throw new MappingFailed('Unsupported event envelope.');
        }
        $result = [
            '@timestamp' => $this->timestamp($raw['occurred_at'] ?? null),
            'ecs' => ['version' => self::ECS_VERSION],
            'event' => ['id' => $raw['event_id'], 'created' => $this->timestamp($raw['observed_at'] ?? null),
                'kind' => 'event', 'code' => $raw['name'], 'action' => $raw['action'], 'outcome' => $raw['outcome'],
                'module' => 'laravel_security_observability', 'dataset' => 'laravel_security_observability.'.$raw['kind'],
                'severity' => match (Severity::from($raw['severity'])) {
                    Severity::Informational => 1, Severity::Warning => 2, Severity::Error => 3, Severity::Critical => 4
                }],
            'log' => ['level' => Severity::from($raw['severity'])->logLevel()],
            'kater' => ['mapper' => ['version' => self::MAPPER_VERSION], 'schema' => ['version' => $raw['schema_version']],
                'kind' => $raw['kind'], 'severity' => $raw['severity']],
        ];
        [$category, $type] = $this->classification($raw['name']);
        if ($category !== []) {
            $result['event']['category'] = $category;
        }
        $result['event']['type'] = $type;
        foreach (['service' => ['service', 'name'], 'environment' => ['service', 'environment'],
            'trace_id' => ['trace', 'id'], 'span_id' => ['span', 'id']] as $from => [$group, $key]) {
            if (is_string($raw[$from] ?? null) && $raw[$from] !== '') {
                $result[$group][$key] = $raw[$from];
            }
        }
        foreach (['correlation_id' => 'correlation', 'request_id' => 'request'] as $from => $to) {
            if (is_string($raw[$from] ?? null)) {
                $result['kater'][$to]['id'] = $raw[$from];
            }
        }
        foreach (['actor', 'target', 'tenant'] as $key) {
            $identity = $raw[$key] ?? null;
            if (is_array($identity) && is_string($identity['type'] ?? null)
                && (is_string($identity['id'] ?? null) || is_int($identity['id'] ?? null))) {
                $result['kater'][$key] = ['type' => $identity['type'], 'id' => (string) $identity['id']];
                if ($identity['type'] === 'user' && $key !== 'tenant') {
                    if ($key === 'actor') {
                        $result['user']['id'] = (string) $identity['id'];
                    } else {
                        $result['user']['target']['id'] = (string) $identity['id'];
                    }
                    $result['related']['user'][] = (string) $identity['id'];
                }
            }
        }
        if (isset($result['related']['user'])) {
            $result['related']['user'] = array_values(array_unique($result['related']['user']));
        }
        $attributes = is_array($raw['attributes'] ?? null) ? $raw['attributes'] : [];
        // Disabled indexing in the example template avoids dynamic field/type explosion.
        $result['kater']['attributes'] = (object) $attributes;
        $ip = $attributes['network']['client_ip'] ?? null;
        if (is_string($ip) && filter_var($ip, FILTER_VALIDATE_IP)) {
            $result['source']['ip'] = $ip;
            $result['related']['ip'] = [$ip];
        }
        $http = $attributes['http'] ?? null;
        if (is_array($http)) {
            if (is_string($http['method'] ?? null) && preg_match('/\A[A-Za-z]{1,32}\z/', $http['method'])) {
                $result['http']['request']['method'] = $http['method'];
            }
            if (is_int($http['status'] ?? null) && $http['status'] >= 100 && $http['status'] <= 599) {
                $result['http']['response']['status_code'] = $http['status'];
            }
            if (isset($result['kater']['request']['id'])) {
                $result['http']['request']['id'] = $result['kater']['request']['id'];
            }
            $duration = $http['duration_ms'] ?? null;
            if ((is_float($duration) || is_int($duration)) && is_finite((float) $duration) && $duration >= 0 && $duration <= 9000000000000) {
                $result['event']['duration'] = (int) round($duration * 1000000);
            }
            // Route templates are not actual URLs; preserve them only in custom attributes.
        }

        return $result;
    }

    private function timestamp(mixed $value): string
    {
        if (! is_string($value)) {
            throw new MappingFailed('Event timestamp is required.');
        }
        $date = DateTimeImmutable::createFromFormat('!Y-m-d\TH:i:s.u\Z', $value);
        if (! $date || $date->format('Y-m-d\TH:i:s.u\Z') !== $value) {
            throw new MappingFailed('Invalid event timestamp.');
        }

        return $value;
    }

    private function classification(string $name): array
    {
        return match (true) {
            str_starts_with($name, 'identity.authentication.'), $name === 'identity.mfa.failed' => [['authentication'], ['info']],
            $name === 'identity.session.ended' => [['session'], ['end']],
            $name === 'access.authorization.denied' => [['iam'], ['info']],
            $name === 'identity.impersonation.started' => [['iam'], ['info']],
            $name === 'identity.impersonation.ended' => [['iam'], ['info']],
            in_array($name, ['identity.mfa.enrolled', 'identity.mfa.removed', 'identity.password.reset', 'identity.credential.rotated', 'identity.credential.revoked', 'identity.privilege.changed'], true) => [['iam'], ['change']],

            str_starts_with($name, 'http.'), str_starts_with($name, 'external_http.') => [['web'], ['access']],
            default => [[], ['info']],
        };
    }
}
