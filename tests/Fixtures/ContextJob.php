<?php

declare(strict_types=1);

namespace Kater\SecurityObservability\Tests\Fixtures;

use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Support\Facades\Queue;
use Kater\SecurityObservability\Context\CorrelationContext;
use RuntimeException;

class ContextJob implements ShouldQueue
{
    public static array $seen = [];

    public function __construct(public bool $nested = false, public bool $fail = false) {}

    public function handle(): void
    {
        self::$seen[] = app(CorrelationContext::class)->snapshot();
        if ($this->nested) {
            try {
                Queue::connection('sync')->push(new self(fail: true));
            } catch (RuntimeException) {
            }
            self::$seen[] = app(CorrelationContext::class)->snapshot();
        }
        if ($this->fail) {
            throw new RuntimeException('synthetic-job-secret');
        }
    }
}
