<?php

declare(strict_types=1);

namespace Kater\SecurityObservability\Tests\Feature;

use Kater\SecurityObservability\Tests\TestCase;

final class ConfigurationOverrideTest extends TestCase
{
    protected function defineEnvironment($app): void
    {
        $app['config']->set('security-observability.service', 'host-service');
        $app['config']->set('security-observability.enabled', true);
    }

    public function test_host_settings_survive_registration(): void
    {
        self::assertSame('host-service', config('security-observability.service'));
        self::assertTrue(config('security-observability.enabled'));
        self::assertFalse(config('security-observability.capture.request_body'));
    }
}
