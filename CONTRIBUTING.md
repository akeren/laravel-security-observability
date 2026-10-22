# Contributing

Use PHP 8.3–8.5 and Composer 2. Install dependencies with `composer update` and
run `composer check`, `composer check-platform-reqs`, and `composer audit`.
Run `vendor/bin/pint` (or `composer format`) before submitting changes.
`composer format:check` checks formatting without modifying files; it also runs
as part of `composer check` and CI. The preset is Laravel, configured in `pint.json`.

CI also tests the minimum supported Laravel version and current Laravel 13,
PHPStan level 5, MySQL/PostgreSQL delivery, source coverage, and targeted mutation
testing. See the README for commands and thresholds. Do not add analysis baselines
or lower quality thresholds to conceal failures.

Keep package code independent of `App\` classes and host business policies.
Use synthetic fixtures only; never include environment files, runtime logs,
credentials, or production data. Add behavior tests for changes. Public contracts
are provisional until the first beta; document changes in CHANGELOG.md.

Do not publish a release until the compatibility matrix is green, the repository
account is confirmed, and package-name availability
has been checked.
