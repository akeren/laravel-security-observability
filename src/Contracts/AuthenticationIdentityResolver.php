<?php

declare(strict_types=1);

namespace Kater\SecurityObservability\Contracts;

use Illuminate\Contracts\Auth\Authenticatable;
use Kater\SecurityObservability\Events\Actor;

interface AuthenticationIdentityResolver
{
    /** Return an identifier, never credentials or the user model itself. */
    public function resolve(Authenticatable $user): ?Actor;
}
