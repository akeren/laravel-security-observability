<?php

declare(strict_types=1);

namespace Kater\SecurityObservability\Events;

/** Verified initiator of an observed action; omit when unknown. */
final readonly class Actor extends Identity {}
