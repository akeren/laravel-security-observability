<?php

declare(strict_types=1);

namespace Kater\SecurityObservability\Tests\Unit;

use Kater\SecurityObservability\Context\CorrelationContext;
use PHPUnit\Framework\TestCase;
use RuntimeException;

final class CorrelationContextTest extends TestCase
{
    public function test_restore_allowlists_fields_and_accepts_only_valid_trace_context(): void
    {
        $context = new CorrelationContext;
        $context->restore(['correlation_id' => 'workflow', 'request_id' => "bad\nrequest", 'tenant' => 'untrusted', 'trace_id' => str_repeat('0', 32), 'span_id' => str_repeat('a', 16)]);
        self::assertSame('workflow', $context->snapshot()['correlation_id']);
        self::assertNotSame("bad\nrequest", $context->snapshot()['request_id']);
        self::assertArrayNotHasKey('tenant', $context->snapshot());
        self::assertArrayNotHasKey('trace_id', $context->snapshot());
        $context->start('workflow', 'request', ['trace_id' => str_repeat('a', 32), 'span_id' => str_repeat('b', 16)]);
        $snapshot = $context->snapshot();
        try {
            $context->within([], fn () => throw new RuntimeException);
        } catch (RuntimeException) {
        }
        self::assertSame($snapshot, $context->snapshot());
        $context->clear();
        self::assertSame([], $context->snapshot());
    }
}
