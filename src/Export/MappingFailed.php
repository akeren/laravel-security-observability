<?php

declare(strict_types=1);

namespace Kater\SecurityObservability\Export;

/** Signals that a sanitized event cannot be represented by the selected output schema. */
class MappingFailed extends \RuntimeException {}
