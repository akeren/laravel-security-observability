<?php

declare(strict_types=1);

namespace Kater\SecurityObservability\Security;

use Illuminate\Contracts\Auth\Authenticatable;
use Kater\SecurityObservability\Contracts\AuthenticationIdentityResolver;
use Kater\SecurityObservability\Events\Actor;

final class AuthenticationIdentity implements AuthenticationIdentityResolver
{
    public function resolve(Authenticatable $user): ?Actor
    {
        $id = $user->getAuthIdentifier();

        return is_string($id) || is_int($id) ? new Actor('user', $id) : null;
    }
}
