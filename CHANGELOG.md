# Changelog

## Unreleased

- Add architecture tests for PSR-4 declarations, dependency boundaries, immutable events,
  contract-based dependencies, and sanitized-event output contracts. Run them with
  `composer test:architecture` or as part of the full test suite and CI.

## 0.1.0 — 2026-10-22

Initial release. Hosted CI, local application integration tests, and the local
event-recording and redaction smoke test passed.

- Reject unknown delivery drivers instead of silently bypassing durable/strict capture.
- Separate export orchestration, HTTP/Elasticsearch transports, and retry policy behind contracts.
- Require `SanitizedEvent` at the sink boundary; custom sinks may retain a broader contravariant parameter.
- Support custom/decorated ECS mappers through `EcsEventMapper`.
- Validate Retry-After dates strictly and bound malformed input.
- Add PHPStan, coverage/mutation gates, and real MySQL/PostgreSQL transaction/concurrency tests.

- Add typed security events, authentication listeners, and explicit host adapters.
- Add optional durable outbox delivery, bounded retries, leases, replay, and health checks.
- Add ECS mapping and tested TLS Elasticsearch/Filebeat ingestion with synthetic SOC scenarios.
- Implement operational event recording and a dedicated JSONL logging channel.
- Add bounded privacy normalization, exact-path redaction, and attribute allowlists.
- Add inbound/outbound HTTP correlation and queue/command lifecycle isolation.
- Test retries, nested sync failures, redirect propagation, and recursion exclusions.
- Verify PHP 8.3–8.5 with Laravel 13.31.0 and 13.37.0 in the independent package.

- Add Laravel Pint formatting with the Laravel preset and enforce it in CI.

- Bootstrap `kater/laravel-security-observability`, authored by Kater Akeren.
- Add PSR-4 autoloading, automatic Laravel provider discovery, and publishable configuration.
- Provide replaceable recorder, sink, mapper, context, and redaction contracts.
- Add Testbench tests, clean-consumer discovery/config-cache verification, and CI.
- Target PHP 8.3–8.5 and Laravel 13.31+; record compatibility evidence and release limitations.
