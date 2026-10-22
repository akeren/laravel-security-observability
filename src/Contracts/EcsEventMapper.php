<?php

declare(strict_types=1);

namespace Kater\SecurityObservability\Contracts;

/** Capability contract for mappers that produce ECS documents with stable event identity. */
interface EcsEventMapper extends EventMapper {}
