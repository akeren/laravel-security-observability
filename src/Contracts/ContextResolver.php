<?php

declare(strict_types=1);

namespace Kater\SecurityObservability\Contracts;

/** Supplies host-owned identities for the current request or job; unknown identities stay absent. */
interface ContextResolver
{
    /**
     * Return scalar identifiers only, never models, credentials, or an unverified login subject.
     * Explicit event identities take precedence over these defaults.
     *
     * @return array{actor?: array{type: string, id: string|int}, target?: array{type: string, id: string|int}, tenant?: array{type: string, id: string|int}}
     */
    public function resolve(): array;
}
