<?php

declare(strict_types=1);

namespace Kater\SecurityObservability\Events;

/** Host-defined tenant boundary; never inferred from credentials or request headers. */
final readonly class Tenant extends Identity {}
