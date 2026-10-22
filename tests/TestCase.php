<?php

declare(strict_types=1);

namespace Kater\SecurityObservability\Tests;

use Kater\SecurityObservability\SecurityObservabilityServiceProvider;
use Orchestra\Testbench\TestCase as Orchestra;

abstract class TestCase extends Orchestra
{
    protected function getPackageProviders($app): array
    {
        return [SecurityObservabilityServiceProvider::class];
    }
}
