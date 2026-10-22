# Compatibility

| Component | Supported or tested versions |
| --- | --- |
| PHP | 8.3, 8.4, 8.5 |
| Laravel | 13.31.0 through 13.x |
| Testbench | 11.x, development only |
| PHPUnit | 12.x, development only |
| Pint | 1.32+, development only |
| ECS | 9.5.0, mapper version 1.0.0 |
| Elasticsearch / Filebeat example | 9.5.5 |

The local PHP/framework matrix passed on PHP 8.3–8.5 with Laravel 13.31.0
and 13.37.0. TLS Elasticsearch/Filebeat ingestion and synthetic investigation
scenarios were verified separately. CI repeats the minimum/latest framework
matrix and the Elastic integration.

Local host adoption was verified on 2026-10-21 with PHP 8.3.35 and Laravel
13.31.0: 78 focused regression tests passed, followed by 23 passing HTTP tests
after the final correlation adjustment. Cached-configuration rollout and rollback
also passed. These results are not production-canary or performance evidence.

Concurrent Octane/Fiber execution and automatic OpenTelemetry context lookup
are not supported. No latency or throughput budget is claimed.

Before publication, run the hosted CI matrix and dependency audit, confirm the
repository/package name, and complete the production
canary. A clean package audit does not establish that a consuming application's
other dependencies are free of advisories.
