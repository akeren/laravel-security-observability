<?php

declare(strict_types=1);

namespace Kater\SecurityObservability\Delivery;

use Illuminate\Http\Client\ConnectionException;
use Kater\SecurityObservability\Contracts\DeliveryTransport;
use Kater\SecurityObservability\Contracts\EventMapper;
use Kater\SecurityObservability\Events\SanitizedEvent;
use Kater\SecurityObservability\Export\MappingFailed;

final class JsonHttpTransport implements DeliveryTransport
{
    public function __construct(private HttpDeliveryClient $client, private EventMapper $mapper) {}

    public function validate(): void
    {
        $this->client->validate();
    }

    public function send(SanitizedEvent $event): DeliveryResult
    {
        try {
            $document = $this->mapper->map($event);

            return $this->client->outcome($this->client->send('POST', $this->client->endpoint(), $event->id(), $document));
        } catch (MappingFailed) {
            return DeliveryResult::quarantine('mapping');
        } catch (ConnectionException) {
            return DeliveryResult::retry('connection');
        }
    }
}
