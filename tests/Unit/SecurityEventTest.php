<?php

declare(strict_types=1);

namespace Kater\SecurityObservability\Tests\Unit;

use InvalidArgumentException;
use Kater\SecurityObservability\Events\Actor;
use Kater\SecurityObservability\Events\SecurityEvent;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class SecurityEventTest extends TestCase
{
    public static function unsafeIds(): array
    {
        return [[''], ["user\nspoof"], ["bad\xff"], [str_repeat('x', 257)]];
    }

    #[DataProvider('unsafeIds')]
    public function test_rejects_unbounded_or_unsafe_identifiers(string $id): void
    {
        $this->expectException(InvalidArgumentException::class);
        new Actor('user', $id);
    }

    public function test_rejects_unstructured_event_names(): void
    {
        $this->expectException(InvalidArgumentException::class);
        new SecurityEvent("login\nspoof", 'authenticate');
    }

    public function test_identifiers_are_immutable_and_do_not_require_models(): void
    {
        $actor = new Actor('service', 'service-uuid');
        $this->expectException(\Error::class);
        $actor->id = 'other';
    }
}
