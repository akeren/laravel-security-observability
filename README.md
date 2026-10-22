# Laravel Security Observability

Structured operational and security-event telemetry for Laravel, by **Kater Akeren**.
Package: `kater/laravel-security-observability` · License: [MIT](LICENSE).

Record privacy-filtered JSON events, correlate requests and queued jobs, and optionally
persist events in a database outbox for HTTPS delivery. ECS output and a working
Elasticsearch/Filebeat example are included. The package observes application actions;
it does not enforce authorization or provide a detection engine.

**Release:** `0.1.1`, adding architecture regression tests without runtime API changes.
The API may evolve during the `0.x` series. Validate configuration and delivery in
your deployment environment before production rollout.

## Requirements

- PHP **8.3–8.5**, Composer 2, and Laravel **13.31+ within 13.x**.
- A database and the published migration when using the outbox.
- Sequential request/job execution. Concurrent Octane/Fiber execution is not supported.

See [compatibility](docs/compatibility.md) for the tested matrix.

## Installation

Install from Packagist once the package is available there:

```sh
composer require kater/laravel-security-observability:^0.1
php artisan vendor:publish --tag=security-observability-config
```

For development, install from a local checkout:

```sh
composer config repositories.security-observability path /absolute/path/to/laravel-security-observability
composer require kater/laravel-security-observability:@dev
php artisan vendor:publish --tag=security-observability-config
```

Laravel discovers the service provider automatically. Telemetry is **disabled by default**.
Enable it in the application's environment:

```dotenv
SECURITY_OBSERVABILITY_ENABLED=true
SECURITY_OBSERVABILITY_SERVICE=my-service
SECURITY_OBSERVABILITY_FORMAT=native
SECURITY_OBSERVABILITY_DRIVER=json
```

The dedicated `security-observability` logging channel writes one JSON object per line
to stderr. Set `SECURITY_OBSERVABILITY_OUTPUT` to a writable file or stream to change
its destination. A custom logging channel must use
`Kater\SecurityObservability\Export\Json\EventJsonFormatter` to preserve root JSON fields.

### HTTP and queue instrumentation

Append the inbound middleware once in the existing `bootstrap/app.php` middleware
configuration, after trusted-proxy middleware:

```php
use Illuminate\Foundation\Configuration\Middleware;
use Kater\SecurityObservability\Http\Middleware\LogIncomingRequest;

->withMiddleware(function (Middleware $middleware): void {
    $middleware->append(LogIncomingRequest::class);
})
```

Applications using an HTTP kernel can add the same class to its global middleware
list instead. Laravel HTTP-client and queue listeners are registered automatically.
Direct Guzzle clients outside Laravel's HTTP factory are not instrumented.

Inbound requests receive fresh server request IDs and response headers
`X-Request-ID` and `X-Correlation-ID`. Incoming correlation IDs are ignored unless
`http.accept_correlation` is enabled. Configure the host's trusted proxies before
relying on the recorded client IP.

Outbound correlation propagation defaults to none. In `config/security-observability.php`,
allow only exact lowercase origins you control:

```php
'http' => [
    'accept_correlation' => false,
    'outbound' => true,
    'propagation_origins' => ['https://api.example.test'],
    'excluded_origins' => [],
],
```

Enabled outbound instrumentation removes `X-Correlation-ID` on unapproved destinations,
including redirects. It does not propagate actor or tenant headers.
Queue telemetry carries correlation/request IDs and optional valid trace/span IDs;
it never adds identities, attributes, or job arguments to its payload extension.
Nested synchronous jobs restore their parent's context. Retries receive distinct
attempt IDs while retaining workflow correlation. Laravel's own job payload is not
sanitized by this package.

## Recording events

Inject `Kater\SecurityObservability\Contracts\EventRecorder`, or resolve it from the container:

```php
use Kater\SecurityObservability\Contracts\EventRecorder;
use Kater\SecurityObservability\Events\OperationalEvent;

app(EventRecorder::class)->record(new OperationalEvent(
    name: 'report.generated',
    attributes: ['format' => 'csv', 'row_count' => 25],
    outcome: 'success',
));
```

Events have a stable UUID, occurrence and observation timestamps, service/environment,
kind, name, action, outcome, severity, and any active correlation context. The native
event schema is `0.2`. Supported outcomes are `success`, `failure`, and `unknown`.
Attribute keys cannot overwrite the event envelope.

### Security events

Use `SecurityEvents` for the supplied action vocabulary, or construct a
`Events\SecurityEvent` for your own stable event name and action:

```php
use Kater\SecurityObservability\Events\Actor;
use Kater\SecurityObservability\Events\Outcome;
use Kater\SecurityObservability\Events\Target;
use Kater\SecurityObservability\Events\Tenant;
use Kater\SecurityObservability\Security\SecurityAction;
use Kater\SecurityObservability\Security\SecurityEvents;

app(SecurityEvents::class)->emit(
    action: SecurityAction::CredentialRotated,
    outcome: Outcome::Success,
    actor: new Actor('user', 'user-123'),
    target: new Target('credential', 'credential-456'),
    tenant: new Tenant('organization', 'organization-789'),
);
```

Emit outcomes after observing the action. Use identifiers, never credential values,
and leave unknown actors absent. Host adapters own identity, tenant, authorization,
and business-policy decisions.

Laravel `Login`, `Failed`, `Logout`, `Lockout`, and `PasswordReset` events are observed
when security/authentication capture is enabled. Custom token and authentication
flows may not emit these events and need explicit adapters. Disable
`security.authentication.enabled` when an adapter would duplicate the framework events.
A failed login does not establish a verified actor.

## Privacy and customization

Automatic capture excludes request/response bodies, query values, headers, raw URL
paths, body hashes, and exception messages/stacks. The `capture` settings cannot
enable these unsupported features. HTTP metadata includes method, status, duration,
inbound route template/name and resolved client IP, or outbound origin.

The privacy pipeline runs before JSON output or outbox persistence:

- Sensitive-key fragments are matched case-insensitively, ignoring punctuation.
- `privacy.redact_paths` accepts exact RFC 6901 pointers such as `/attributes/customer/email`.
- `privacy.allowed_attribute_keys`: `null` allows all attributes through redaction;
  `[]` excludes all attributes; a list permits only those top-level keys.
- String size, collection entries, nesting depth, visited nodes, and total event
  bytes are bounded. Unsupported objects/resources are not serialized through callbacks.
- Events that exceed the final byte limit or corrupt envelope identity are rejected.

Prefer attribute allowlists. Key/path filters cannot detect every secret embedded
in arbitrary text. Identifiers and IP addresses may still require a host-specific
privacy policy; automatic pseudonymization is not provided.

The container contracts `ContextResolver`, `AuthenticationIdentityResolver`, `Redactor`,
`EventMapper`, `EventSink`, `EventRecorder`, `DeliveryStore`, `DeliveryTransport`,
and `RetryPolicy` support custom bindings. The default
context resolver returns no identity. A custom resolver supplies only `actor`,
`target`, and `tenant` identity arrays. Custom redactors must retain normalization,
bounds, and envelope integrity. Custom sinks accept `Events\SanitizedEvent`; mappers run after redaction.
Custom ECS mappers implement `Contracts\EcsEventMapper`, including decorators.
Export orchestration depends on delivery-store, transport, and retry-policy contracts,
so adding a transport does not require editing the exporter. For a custom durable
backend, bind both `EventSink` for capture and `DeliveryStore` for leased delivery. See the PHPDoc on the contracts for extension requirements.

## Durable delivery

JSON is the default and requires no migration. Invalid delivery-driver values are
rejected as configuration errors, including when a custom sink is bound; they never
silently fall back to JSON. To enable the outbox:

```sh
php artisan vendor:publish --tag=security-observability-migrations
php artisan migrate
```

Review the migration and choose the database connection before deployment. Configure:

```dotenv
SECURITY_OBSERVABILITY_DRIVER=outbox
SECURITY_OBSERVABILITY_ENDPOINT=https://collector.example.test/events
SECURITY_OBSERVABILITY_AUTH_SCHEME=Bearer
SECURITY_OBSERVABILITY_TOKEN=your-collector-token
```

The HTTP transport sends one JSON event per request. TLS verification is always
required and redirects are disabled. `SECURITY_OBSERVABILITY_CA_BUNDLE` can select a
custom CA file. Authentication schemes are `Bearer` and `ApiKey`.

Schedule an export command in the application's `routes/console.php`:

```php
use Illuminate\Support\Facades\Schedule;

Schedule::command('security-observability:delivery export')
    ->everyMinute()
    ->withoutOverlapping();
```

Run Laravel's scheduler in deployment. Alternatively dispatch
`new Kater\SecurityObservability\Delivery\ExportOutbox` to a configured queue with a
running worker. The job dispatches after commit and excludes its own telemetry.
Exports process bounded batches; choose a cadence and batch size suitable for volume.

Same-connection outbox inserts participate in the application's database transaction.
Use an independently configured `delivery.connection` for observations that must
survive business-transaction rollback. Exporting must run outside business transactions.

Operational capture is fail-open. Security capture is also fail-open unless
`delivery.strict_security` is enabled, in which case rejected or unpersisted security
events throw `Delivery\PersistenceFailed`. Strict persistence does not guarantee
successful remote delivery. Monitor storage, backlog, rejected events, and quarantines.

Delivery uses leases, bounded retries/backoff, and quarantine for permanent failures.
Consumers should deduplicate using `event_id`: retries can deliver an event more than
once. Pending and quarantined records are never removed by retention pruning.
Capacity limits reject new events when the outbox fills.

```sh
php artisan security-observability:delivery health
php artisan security-observability:delivery export
php artisan security-observability:delivery inspect --id=EVENT_UUID
php artisan security-observability:delivery replay --id=EVENT_UUID
php artisan security-observability:delivery prune
```

Inspection omits payloads. Replay accepts quarantined events and preserves their IDs.
Prune removes only delivered records older than the configured retention period.
`TelemetryState::$failures` and `$rejected` are process-local counters, not persistent
cross-worker metrics.

### ECS and Elasticsearch

Set `SECURITY_OBSERVABILITY_FORMAT=ecs` for ECS output. For direct Elasticsearch delivery:

```dotenv
SECURITY_OBSERVABILITY_DRIVER=outbox
SECURITY_OBSERVABILITY_FORMAT=ecs
SECURITY_OBSERVABILITY_TRANSPORT=elasticsearch
SECURITY_OBSERVABILITY_ENDPOINT=https://elastic.example.test/security-events/_doc
SECURITY_OBSERVABILITY_AUTH_SCHEME=ApiKey
```

The exporter uses the event UUID as the document ID and validates the acknowledgement.
The [Elastic example](examples/elastic/README.md) includes pinned ECS/backend versions,
TLS setup, Filebeat collection, mappings, and synthetic investigation queries.

## Rollout and rollback

Use a reviewed tagged version for deployments; path repositories are for development.
Start with JSON on a canary and verify event counts, redaction, and application behavior
before enabling durable delivery. Replace existing middleware/listeners deliberately
to avoid duplicate events.

After changing configuration, rebuild the host's cached configuration and restart
long-lived workers. To stop new capture, set `SECURITY_OBSERVABILITY_ENABLED=false`.
This also stops the package exporter. Preserve unresolved outbox records and retain a
compatible exporter for controlled draining; do not drop the tables during rollback.
Host-specific legacy/package switches are not provided by this library.

## Development

```sh
composer update
vendor/bin/pint
composer check
composer check-platform-reqs
composer audit
```

CI tests PHP 8.3–8.5 against the minimum and latest supported Laravel 13 versions.
`composer check` runs Composer validation, Pint, PHPStan level 5, PHPUnit, and an independent Laravel
consumer smoke test covering discovery and cached configuration. The consumer test
requires network access and cleans up its temporary application. Run the separate
Elastic integration using the instructions in its example directory.

Additional quality checks:

```sh
# Requires Xdebug coverage mode; reports are written to build/.
XDEBUG_MODE=coverage composer test:coverage
XDEBUG_MODE=coverage composer test:mutation

# Disposable localhost databases with synthetic credentials only.
docker compose -f tests/Integration/database-compose.yml up -d --wait
SECURITY_TEST_DB_DRIVER=mysql composer test:database
SECURITY_TEST_DB_DRIVER=pgsql composer test:database
docker compose -f tests/Integration/database-compose.yml down -v
```

CI requires at least 90% source line coverage. Mutation testing currently targets
`DeliveryDriver` and `RetryPolicy`, with 80% overall and 85% covered-mutation score
thresholds. This measures those critical policy tests, not every package branch.
The MySQL 8.4/PostgreSQL 17 suites cover transactions, independent connections,
lease recovery, competing workers, and concurrent capacity enforcement.

The library does not commit its local `composer.lock`; applications should commit
their own lockfiles. Tests and CI remain in the repository but are excluded from release archives.
The synthetic Elastic example is included; its generated credentials and runtime files are not. See [contributing](CONTRIBUTING.md),
[changes](CHANGELOG.md), and the [security policy](SECURITY.md).
