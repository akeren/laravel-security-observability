<?php

declare(strict_types=1);

namespace Kater\SecurityObservability\Delivery;

use Illuminate\Http\Client\ConnectionException;
use Kater\SecurityObservability\Contracts\DeliveryTransport;
use Kater\SecurityObservability\Contracts\EcsEventMapper;
use Kater\SecurityObservability\Contracts\EventMapper;
use Kater\SecurityObservability\Events\SanitizedEvent;
use Kater\SecurityObservability\Export\MappingFailed;
use LogicException;

final class ElasticsearchTransport implements DeliveryTransport
{
    public function __construct(private HttpDeliveryClient $client, private EventMapper $mapper) {}

    public function validate(): void
    {
        $this->client->validate();
        $parts = parse_url($this->client->endpoint());
        if (! $this->mapper instanceof EcsEventMapper || ! str_ends_with($parts['path'] ?? '', '/_doc') || isset($parts['query'])) {
            throw new LogicException('Elasticsearch transport requires ECS and an index /_doc endpoint.');
        }
    }

    public function send(SanitizedEvent $event): DeliveryResult
    {
        try {
            $document = $this->mapper->map($event);
            $response = $this->client->send('PUT', $this->client->endpoint().'/'.rawurlencode($event->id()), $event->id(), $document);
            if ($response->successful() && ($response->json('_id') !== $event->id()
                || ! in_array($response->json('result'), ['created', 'updated'], true)
                || $response->json('_shards.failed') !== 0)) {
                return DeliveryResult::retry('invalid_acknowledgment');
            }

            return $this->client->outcome($response);
        } catch (MappingFailed) {
            return DeliveryResult::quarantine('mapping');
        } catch (ConnectionException) {
            return DeliveryResult::retry('connection');
        }
    }
}
