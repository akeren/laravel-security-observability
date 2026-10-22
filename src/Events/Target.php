<?php

declare(strict_types=1);

namespace Kater\SecurityObservability\Events;

/** Resource or subject affected by an action, including an unverified login subject. */
final readonly class Target extends Identity {}
