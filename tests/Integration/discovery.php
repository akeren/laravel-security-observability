<?php

declare(strict_types=1);

require __DIR__.'/../../vendor/autoload.php';

use Composer\InstalledVersions;
use Symfony\Component\Process\Process;

// A real Composer consumer, with no manually registered package provider.
$root = dirname(__DIR__, 2);
$directory = sys_get_temp_dir().'/security-observability-'.bin2hex(random_bytes(6));
mkdir($directory, 0700, true);
foreach (['bootstrap/cache', 'storage/framework/views', 'storage/framework/cache', 'storage/logs', 'config'] as $path) {
    mkdir($directory.'/'.$path, 0700, true);
}
$composer = [
    'name' => 'kater/discovery-smoke-test',
    'type' => 'project',
    'repositories' => [['type' => 'path', 'url' => $root, 'options' => ['symlink' => true, 'versions' => ['kater/laravel-security-observability' => 'dev-main']]]],
    'require' => [
        'laravel/framework' => InstalledVersions::getPrettyVersion('laravel/framework'),
        'kater/laravel-security-observability' => 'dev-main',
    ],
    'config' => ['allow-plugins' => false],
];
file_put_contents($directory.'/composer.json', json_encode($composer, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));
file_put_contents($directory.'/bootstrap/app.php', <<<'PHP'
<?php
return Illuminate\Foundation\Application::configure(basePath: dirname(__DIR__))
    ->withProviders([])->create();
PHP);
file_put_contents($directory.'/artisan', <<<'PHP'
<?php
require __DIR__.'/vendor/autoload.php';
$app = require __DIR__.'/bootstrap/app.php';
exit($app->handleCommand(new Symfony\Component\Console\Input\ArgvInput));
PHP);
file_put_contents($directory.'/verify.php', <<<'PHP'
<?php
require __DIR__.'/vendor/autoload.php';
$app = require __DIR__.'/bootstrap/app.php';
$app->make(Illuminate\Contracts\Console\Kernel::class)->bootstrap();
if (!$app->getProvider(Kater\SecurityObservability\SecurityObservabilityServiceProvider::class)) {
    throw new RuntimeException('Package was not automatically discovered.');
}
if ($app['config']->get('security-observability.capture.request_body') !== false) {
    throw new RuntimeException('Safe defaults were not loaded.');
}
if ($app['config']->get('security-observability.service') !== 'consumer-service') {
    throw new RuntimeException('Consumer configuration was not preserved.');
}
$app->make(Kater\SecurityObservability\Contracts\EventRecorder::class)->record(
    new Kater\SecurityObservability\Events\OperationalEvent('consumer.ready', ['token' => 'synthetic-secret'])
);
$lines = file($app['config']->get('security-observability.output'), FILE_IGNORE_NEW_LINES);
$event = json_decode(end($lines), true, flags: JSON_THROW_ON_ERROR);
if ($event['name'] !== 'consumer.ready' || $event['attributes']['token'] !== '[REDACTED]') {
    throw new RuntimeException('Discovered recorder did not emit sanitized structured JSON.');
}
$app['events']->dispatch(new Illuminate\Auth\Events\Login('web', new Illuminate\Auth\GenericUser(['id' => 'synthetic-user', 'password' => 'synthetic-password']), false));
$lines = file($app['config']->get('security-observability.output'), FILE_IGNORE_NEW_LINES);
$event = json_decode(end($lines), true, flags: JSON_THROW_ON_ERROR);
if ($event['kind'] !== 'security' || $event['name'] !== 'identity.authentication.succeeded' || $event['actor']['id'] !== 'synthetic-user'
    || str_contains(end($lines), 'synthetic-password')) {
    throw new RuntimeException('Discovered authentication listener did not emit a safe security event.');
}
PHP);
$run = static function (array $command) use ($directory): void {
    $process = new Process($command, $directory, ['SECURITY_OBSERVABILITY_SERVICE' => 'consumer-service', 'SECURITY_OBSERVABILITY_ENABLED' => 'true', 'SECURITY_OBSERVABILITY_OUTPUT' => $directory.'/storage/logs/telemetry.jsonl']);
    $process->setTimeout(300);
    $process->mustRun(static function ($type, $output): void {
        echo $output;
    });
};
try {
    $run(['composer', 'update', '--no-dev', '--no-interaction', '--prefer-dist', '--no-progress']);
    $run([PHP_BINARY, 'artisan', 'package:discover', '--ansi']);
    $run([PHP_BINARY, 'artisan', 'vendor:publish', '--tag=security-observability-config', '--force']);
    if (! is_file($directory.'/config/security-observability.php')) {
        throw new RuntimeException('Configuration publishing failed.');
    }
    $run([PHP_BINARY, 'verify.php']);
    $run([PHP_BINARY, 'artisan', 'config:cache']);
    $run([PHP_BINARY, 'verify.php']);
    $run([PHP_BINARY, 'artisan', 'vendor:publish', '--tag=security-observability-migrations', '--force']);
    if (! is_file($directory.'/database/migrations/2026_10_18_000000_create_security_observability_outbox.php')) {
        throw new RuntimeException('Outbox migration publishing failed.');
    }
    file_put_contents($directory.'/verify-delivery.php', <<<'PHP'
<?php
require __DIR__.'/vendor/autoload.php';
$app = require __DIR__.'/bootstrap/app.php';
$app->make(Illuminate\Contracts\Console\Kernel::class)->bootstrap();
$app['config']->set('database.default', 'delivery-test');
$app['config']->set('database.connections.delivery-test', ['driver' => 'sqlite', 'database' => ':memory:', 'prefix' => '']);
$app['config']->set('security-observability.delivery.driver', 'outbox');
$app['config']->set('security-observability.delivery.connection', 'delivery-test');
(require __DIR__.'/database/migrations/2026_10_18_000000_create_security_observability_outbox.php')->up();
$app->make(Kater\SecurityObservability\Contracts\EventRecorder::class)->record(new Kater\SecurityObservability\Events\SecurityEvent('consumer.delivery', 'observe', attributes: ['password' => 'synthetic-secret']));
$outbox = $app->make(Kater\SecurityObservability\Delivery\Outbox::class);
$row = $outbox->rows()->first();
if (! $row || str_contains($row->payload, 'synthetic-secret')) {
    throw new RuntimeException('Discovered outbox did not persist sanitized event.');
}
if ($app->make(Illuminate\Contracts\Console\Kernel::class)->call('security-observability:delivery', ['action' => 'health']) !== 0) {
    throw new RuntimeException('Delivery command was not discovered.');
}
PHP);
    $run([PHP_BINARY, 'verify-delivery.php']);
    echo "Clean consumer discovery, publishing, config caching, sanitized JSON recording, authentication listeners, and outbox installation passed.\n";
} finally {
    // Do not follow the Composer path repository symlink back into the package.
    $remove = static function (string $path) use (&$remove): void {
        if (is_link($path) || ! is_dir($path)) {
            unlink($path);

            return;
        }
        foreach (new FilesystemIterator($path) as $entry) {
            $remove($entry->getPathname());
        }
        rmdir($path);
    };
    $remove($directory);
}
