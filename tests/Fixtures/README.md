# Synthetic extraction fixtures

`legacy-operational.json` was generated on 2026-10-18 by invoking the original
`CorrelationContext`, `SensitiveDataRedactor`, and `StructuredLogger` with a
capturing PSR logger. Inputs were invented: `synthetic-workflow`,
`synthetic-request`, `synthetic-secret`, `synthetic-card`, and `synthetic-token`.
The time was normalized to `2026-01-01T00:00:00+00:00` after capture. No application
bootstrap, environment file, database, runtime log, or production data was loaded.

The fixture preserves correlation IDs, event naming, and nested key redaction
for comparison in `RecorderTest`. Intentional changes from the legacy behavior:

- `event` becomes `name`, `context` becomes `attributes`, and structured output
  has no JSON string inside a logging message.
- HTTP automatic capture excludes bodies, fingerprints, headers, and query values.
- Server request IDs are regenerated; upstream correlation requires opt-in and
  validation. Outgoing propagation is restricted to exact origins.
- Queue context ends at the attempt-finally boundary rather than only success or
  terminal failure, so retriable exceptions cannot leak state.

The PHP fixtures are package-local synthetic jobs and a capturing sink used to
exercise Laravel's actual dispatch/worker lifecycle. They have no source-application
imports or business behavior.
