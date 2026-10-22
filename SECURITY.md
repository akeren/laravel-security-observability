# Security policy

Security fixes target the latest patch of the current release series, `0.1.x`;
older minor series are not maintained.
Use the latest available patch and validate deployment-specific configuration.

Operational telemetry is fail-open;
optional strict security capture propagates persistence failures. Outbox capacity
and failed delivery require monitoring. See the README and configuration for
capture coverage, failure policies, and privacy limits.

Report suspected vulnerabilities privately to the package author, Kater Akeren,
at akeren.dev@gmail.com (the Composer author contact). Do not open a public issue
containing exploit details, credentials, customer data, or production logs.
Include the affected package version or commit, PHP and Laravel versions, a
synthetic reproduction, and the expected impact.

The author has confirmed this private reporting address. Reports should remain
private while the issue is assessed and a fix is coordinated. Security fixes and
affected versions will be identified in release notes.

The API may evolve during the `0.x` series. Security maintenance does not guarantee
remote event delivery or replace monitoring of outbox capacity and delivery failures.
