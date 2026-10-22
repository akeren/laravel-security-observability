<?php

declare(strict_types=1);

namespace Kater\SecurityObservability\Events;

use InvalidArgumentException;

abstract readonly class Identity
{
    /**
     * @param  string  $type  Stable lowercase type, up to 64 ASCII characters.
     * @param  string|int  $id  Non-secret identifier; strings must be valid UTF-8, nonempty, and at most 256 bytes.
     *
     * @throws InvalidArgumentException When the type or identifier is invalid.
     */
    public function __construct(public string $type, public string|int $id)
    {
        if (! preg_match('/\A[a-z][a-z0-9_.-]{0,63}\z/', $type)
            || (is_string($id) && ($id === '' || strlen($id) > 256 || preg_match('//u', $id) !== 1 || preg_match('/[\x00-\x1f\x7f]/', $id)))) {
            throw new InvalidArgumentException('Identity requires a type and a bounded scalar identifier.');
        }
    }

    /** @return array{type: string, id: string|int} */
    public function toArray(): array
    {
        return ['type' => $this->type, 'id' => $this->id];
    }
}
