<?php

declare(strict_types=1);

namespace Kater\SecurityObservability\Export\Json;

use Monolog\Formatter\FormatterInterface;
use Monolog\LogRecord;

final class EventJsonFormatter implements FormatterInterface
{
    public function format(LogRecord $record): string
    {
        return json_encode($record->context['event'], JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES | JSON_PRESERVE_ZERO_FRACTION)."\n";
    }

    public function formatBatch(array $records): string
    {
        return implode('', array_map($this->format(...), $records));
    }
}
