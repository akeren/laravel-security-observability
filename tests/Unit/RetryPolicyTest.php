<?php

declare(strict_types=1);

namespace Kater\SecurityObservability\Tests\Unit;

use Illuminate\Config\Repository;
use Kater\SecurityObservability\Delivery\RetryPolicy;
use PHPUnit\Framework\TestCase;
use Random\Engine\Mt19937;
use Random\Randomizer;

final class RetryPolicyTest extends TestCase
{
    public function test_default_and_minimum_attempt_limits(): void
    {
        $config = new Repository;
        $policy = new RetryPolicy($config, new Randomizer(new Mt19937(42)));
        self::assertSame(10, $policy->attempts());
        $config->set('security-observability.delivery.max_attempts', 0);
        self::assertSame(1, $policy->attempts());
        $config->set('security-observability.delivery.max_attempts', 3);
        self::assertSame(3, $policy->attempts());
    }

    public function test_retry_after_cannot_escape_limits_or_force_an_immediate_retry(): void
    {
        $config = new Repository(['security-observability' => ['delivery' => ['max_backoff' => 10, 'base_backoff' => 2]]]);
        $policy = new RetryPolicy($config, new Randomizer(new Mt19937(42)));
        self::assertSame(10, $policy->delay(1, '999999999999999999999999999'));
        self::assertSame(10, $policy->delay(1, gmdate('D, d M Y H:i:s', time() + 3600).' GMT'));
        foreach ([null, 'invalid', '-1', '0', "\0", "120\0", str_repeat('9', 129), 'Thu, 01 Jan 1970 00:00:00 GMT'] as $header) {
            $delay = $policy->delay(1, $header);
            self::assertGreaterThanOrEqual(1, $delay);
            self::assertLessThanOrEqual(2, $delay);
        }
        self::assertSame(8, $policy->delay(1, '8'));
        self::assertSame(10, $policy->delay(1, str_repeat('9', 128)));
        self::assertSame(10, $policy->delay(1, str_repeat('9', 127)));
        self::assertGreaterThanOrEqual(5, $policy->delay(PHP_INT_MAX, null));
        self::assertLessThanOrEqual(10, $policy->delay(PHP_INT_MAX, null));
    }

    public function test_default_jitter_range_and_exponential_growth_are_observable(): void
    {
        $policy = new RetryPolicy(new Repository, new Randomizer(new Mt19937(42)));
        $first = $second = [];
        for ($i = 0; $i < 128; $i++) {
            $first[] = $policy->delay(1, null);
            $second[] = $policy->delay(2, null);
        }
        $first = array_values(array_unique($first));
        $second = array_values(array_unique($second));
        sort($first);
        sort($second);
        self::assertSame([3, 4, 5], $first);
        self::assertSame([5, 6, 7, 8, 9, 10], $second);
        self::assertSame(3600, $policy->delay(99, '999999'));
    }

    public function test_extreme_attempts_remain_inside_the_absolute_backoff_cap(): void
    {
        $policy = new RetryPolicy(new Repository(['security-observability' => ['delivery' => ['max_backoff' => PHP_INT_MAX, 'base_backoff' => 1]]]),
            new Randomizer(new Mt19937(42)));
        for ($i = 0; $i < 64; $i++) {
            $delay = $policy->delay(PHP_INT_MAX, null);
            self::assertGreaterThanOrEqual(43200, $delay);
            self::assertLessThanOrEqual(86400, $delay);
        }
    }

    public function test_minimum_cap_and_minimum_base_are_enforced_independently(): void
    {
        $cap = new RetryPolicy(new Repository(['security-observability' => ['delivery' => ['max_backoff' => 0, 'base_backoff' => 10]]]),
            new Randomizer(new Mt19937(42)));
        $base = new RetryPolicy(new Repository(['security-observability' => ['delivery' => ['max_backoff' => 10, 'base_backoff' => 0]]]),
            new Randomizer(new Mt19937(42)));
        for ($i = 0; $i < 64; $i++) {
            self::assertSame(1, $cap->delay(1, null));
            self::assertSame(1, $base->delay(1, null));
        }
    }

    public function test_invalid_bounds_are_clamped_and_exponent_is_bounded(): void
    {
        $config = new Repository(['security-observability' => ['delivery' => ['max_backoff' => 0, 'base_backoff' => -1]]]);
        $policy = new RetryPolicy($config, new Randomizer(new Mt19937(42)));
        self::assertSame(1, $policy->delay(0, null));
        $config->set('security-observability.delivery.max_backoff', PHP_INT_MAX);
        self::assertSame(86400, $policy->delay(99, '999999'));
    }
}
