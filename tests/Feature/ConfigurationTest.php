<?php

declare(strict_types=1);

namespace Kater\SecurityObservability\Tests\Feature;

use Illuminate\Support\ServiceProvider;
use Kater\SecurityObservability\SecurityObservabilityServiceProvider;
use Kater\SecurityObservability\Tests\TestCase;

final class ConfigurationTest extends TestCase
{
    public function test_safe_defaults_are_loaded(): void
    {
        self::assertFalse(config('security-observability.enabled'));
        foreach (config('security-observability.capture') as $capture) {
            self::assertFalse($capture);
        }
    }

    public function test_configuration_is_publishable(): void
    {
        $paths = ServiceProvider::pathsToPublish(SecurityObservabilityServiceProvider::class, 'security-observability-config');
        self::assertCount(1, $paths);
        self::assertSame(config_path('security-observability.php'), array_values($paths)[0]);
        self::assertFileExists(array_keys($paths)[0]);
    }
}
