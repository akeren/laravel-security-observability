<?php

declare(strict_types=1);

namespace Kater\SecurityObservability\Events;

enum Outcome: string
{
    case Success = 'success';
    case Failure = 'failure';
    case Unknown = 'unknown';
}
