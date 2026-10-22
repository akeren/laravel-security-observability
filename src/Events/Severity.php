<?php

declare(strict_types=1);

namespace Kater\SecurityObservability\Events;

enum Severity: string
{
    case Informational = 'informational';
    case Warning = 'warning';
    case Error = 'error';
    case Critical = 'critical';

    public function logLevel(): string
    {
        return match ($this) {
            self::Informational => 'info',
            self::Warning => 'warning',
            self::Error => 'error',
            self::Critical => 'critical',
        };
    }
}
