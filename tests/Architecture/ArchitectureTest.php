<?php

declare(strict_types=1);

namespace Kater\SecurityObservability\Tests\Architecture;

use Kater\SecurityObservability\Contracts\ContextResolver;
use Kater\SecurityObservability\Contracts\DeliveryStore;
use Kater\SecurityObservability\Contracts\DeliveryTransport;
use Kater\SecurityObservability\Contracts\EventMapper;
use Kater\SecurityObservability\Contracts\EventSink;
use Kater\SecurityObservability\Contracts\Redactor;
use Kater\SecurityObservability\Contracts\RetryPolicy;
use Kater\SecurityObservability\Delivery\Exporter;
use Kater\SecurityObservability\Events\SanitizedEvent;
use Kater\SecurityObservability\Recorder;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use RecursiveDirectoryIterator;
use RecursiveIteratorIterator;
use ReflectionClass;
use ReflectionNamedType;

final class ArchitectureTest extends TestCase
{
    public static function sourceFiles(): iterable
    {
        $root = dirname(__DIR__, 2).'/src/';
        foreach (new RecursiveIteratorIterator(new RecursiveDirectoryIterator($root)) as $file) {
            if ($file->isFile() && $file->getExtension() === 'php') {
                $relative = substr($file->getPathname(), strlen($root));
                yield $relative => [$file->getPathname(), 'Kater\\SecurityObservability\\'.str_replace('/', '\\', substr($relative, 0, -4))];
            }
        }
    }

    #[DataProvider('sourceFiles')]
    public function test_source_declarations_follow_psr4_and_layer_boundaries(string $path, string $class): void
    {
        $reflection = new ReflectionClass($class);
        self::assertSame(realpath($path), $reflection->getFileName());

        if (str_contains($class, '\\Contracts\\')) {
            self::assertTrue($reflection->isInterface(), "$class must remain an extension interface.");
        }
        if (str_contains($class, '\\Events\\') && ! $reflection->isEnum()) {
            self::assertTrue($reflection->isReadOnly(), "$class must remain immutable.");
        }

        // Inspect PHP name tokens rather than comments or string examples.
        foreach (token_get_all(file_get_contents($path), TOKEN_PARSE) as $token) {
            if (! is_array($token) || ! in_array($token[0], [T_NAME_QUALIFIED, T_NAME_FULLY_QUALIFIED], true)) {
                continue;
            }
            $dependency = ltrim($token[1], '\\');
            foreach (['App\\', 'Tests\\', 'Kater\\SecurityObservability\\Tests\\'] as $forbidden) {
                self::assertFalse(str_starts_with($dependency, $forbidden), "$class depends on application/test code: $dependency");
            }
            if (str_contains($class, '\\Events\\') || str_contains($class, '\\Privacy\\')) {
                foreach (['Delivery', 'Export', 'Http', 'Queue', 'Console', 'Security'] as $layer) {
                    self::assertFalse(str_starts_with($dependency, 'Kater\\SecurityObservability\\'.$layer.'\\'), "$class depends on outer layer $dependency");
                }
                foreach (['Illuminate\\Database\\', 'Illuminate\\Http\\', 'Illuminate\\Support\\Facades\\', 'Monolog\\', 'GuzzleHttp\\'] as $forbidden) {
                    self::assertFalse(str_starts_with($dependency, $forbidden), "$class depends on infrastructure: $dependency");
                }
            }
        }
    }

    public function test_exporter_and_recorder_receive_replaceable_policies_through_contracts(): void
    {
        foreach ([Exporter::class => [DeliveryStore::class, DeliveryTransport::class, RetryPolicy::class],
            Recorder::class => [ContextResolver::class, Redactor::class, EventSink::class]] as $class => $required) {
            $dependencies = [];
            foreach ((new ReflectionClass($class))->getConstructor()->getParameters() as $parameter) {
                $type = $parameter->getType();
                self::assertInstanceOf(ReflectionNamedType::class, $type);
                $dependencies[] = $type->getName();
                if (str_starts_with($type->getName(), 'Kater\\SecurityObservability\\Delivery\\')
                    || str_starts_with($type->getName(), 'Kater\\SecurityObservability\\Export\\')
                    || str_starts_with($type->getName(), 'Kater\\SecurityObservability\\Privacy\\')) {
                    self::fail("$class depends on concrete infrastructure {$type->getName()}.");
                }
            }
            foreach ($required as $contract) {
                self::assertContains($contract, $dependencies);
            }
        }
    }

    public function test_output_contracts_require_sanitized_events(): void
    {
        foreach ([EventSink::class => 'write', EventMapper::class => 'map', DeliveryTransport::class => 'send'] as $contract => $method) {
            $type = (new ReflectionClass($contract))->getMethod($method)->getParameters()[0]->getType();
            self::assertInstanceOf(ReflectionNamedType::class, $type);
            self::assertSame(SanitizedEvent::class, $type->getName());
            self::assertFalse($type->allowsNull());
        }
    }
}
