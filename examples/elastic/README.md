# Local Elastic integration

Pinned: Elasticsearch/Filebeat 9.5.5, [ECS 9.5.0](https://github.com/elastic/ecs/releases/tag/v9.5.0), mapper 1.0.0. Synthetic data only; Docker and OpenSSL are required.

```sh
sh examples/elastic/setup.sh
composer test:elastic
docker compose -f examples/elastic/compose.yml down -v
```

The test installs `index-template.json` and `ingest-pipeline.json`, emits synthetic security/HTTP/queue events, runs `queries.json`, verifies duplicate IDs through direct delivery and Filebeat, and stops/restarts Elasticsearch to verify outbox recovery. It resets only the example's two synthetic indices. Certificates and a random local password are generated under ignored `.runtime/`; certificates expire after seven days. Remove that directory after stopping the example to regenerate them. Filebeat uses a local administrator account for this disposable test; use separately provisioned, restricted credentials in a real deployment.

For direct delivery, set `SECURITY_OBSERVABILITY_ENABLED=true`, `SECURITY_OBSERVABILITY_DRIVER=outbox`, `SECURITY_OBSERVABILITY_FORMAT=ecs`, `SECURITY_OBSERVABILITY_TRANSPORT=elasticsearch`, and an HTTPS endpoint ending in `/your-index/_doc`. Set `SECURITY_OBSERVABILITY_AUTH_SCHEME=ApiKey`, the encoded API key in `SECURITY_OBSERVABILITY_TOKEN`, and optionally `SECURITY_OBSERVABILITY_CA_BUNDLE`. Publish/run the outbox migration and schedule `security-observability:delivery export` or `ExportOutbox`. The destination index needs the supplied template. Delivery uses PUT with the stable event ID; changing indices or rollover boundaries changes the deduplication scope.

For file collection, select `format=ecs` with the default JSON driver and write to a dedicated JSONL file. Install `ingest-pipeline.json` as `security-observability-ecs-v1`, create the collector index using `collector-index.json` to set its `index.default_pipeline`, and adapt `filebeat.yml` paths and credentials. Nested decoding plus the ingest pipeline preserves original timestamp precision. The collector uses `event.id` as document ID; it does not give the application an outbox durability guarantee.

Mapping: `occurred_at` → `@timestamp`, `observed_at` → `event.created`, name → `event.code`, action/outcome → corresponding ECS fields. Security observations remain `event.kind=event`. Known names receive ECS categories/types; unknown names omit category. Severity uses package ordinals 1/2/3/4 (informational/warning/error/critical), independently of outcome. HTTP durations convert milliseconds to nanoseconds; the template uses `date_nanos` for timestamps. Actor type `user` maps to `user.id`; attempted/affected users map to `user.target.id`. Generic identities, tenants, request/correlation IDs and mapper/schema versions remain under `kater`. Trace/span IDs are preserved, never fabricated. Redacted attributes are retained under `kater.attributes` with indexing disabled to prevent dynamic field growth. Route templates are not mapped as actual URLs.

The queries are investigation examples, not detection rules. The credential-reuse observation must be supplied by the host. Pseudonymous fixture IDs are synthetic; the package does not automatically pseudonymize identifiers. This is a tested ECS subset, not a claim of complete Elastic Security integration or coverage.
