<?php

declare(strict_types=1);

namespace Kater\SecurityObservability\Contracts;

/** Normalizes untrusted values and redacts sensitive data while preserving envelope identity. */
interface Redactor
{
    /**
     * Implementations must bound traversal and output, and must not invoke object callbacks.
     *
     * @param  array<string, mixed>  $data
     * @return array<string, mixed> JSON-safe values, with event identity fields unchanged.
     */
    public function redact(array $data): array;
}
