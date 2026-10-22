<?php

declare(strict_types=1);

namespace Kater\SecurityObservability\Delivery;

use Illuminate\Contracts\Config\Repository;
use Illuminate\Http\Client\Factory;
use Illuminate\Http\Client\Response;
use LogicException;

/** Shared TLS, credentials, and timeout policy for HTTP-based transports. */
final class HttpDeliveryClient
{
    public function __construct(private Factory $http, private Repository $config) {}

    public function endpoint(): string
    {
        $url = $this->config->get('security-observability.delivery.endpoint');
        $parts = is_string($url) ? parse_url($url) : false;
        if (! $parts || ($parts['scheme'] ?? '') !== 'https' || empty($parts['host']) || isset($parts['user']) || isset($parts['pass']) || isset($parts['fragment'])) {
            throw new LogicException('An HTTPS exporter endpoint without embedded credentials is required.');
        }

        return $url;
    }

    public function validate(): void
    {
        $this->endpoint();
        if (! in_array($this->config->get('security-observability.delivery.auth_scheme', 'Bearer'), ['Bearer', 'ApiKey'], true)) {
            throw new LogicException('Unsupported exporter authentication scheme.');
        }
        $ca = $this->config->get('security-observability.delivery.ca_bundle');
        if ($ca !== null && (! is_string($ca) || ! is_file($ca) || ! is_readable($ca))) {
            throw new LogicException('Exporter CA bundle is not readable.');
        }
    }

    public function send(string $method, string $url, string $id, array $document): Response
    {
        $request = $this->http->withOptions(['verify' => $this->config->get('security-observability.delivery.ca_bundle') ?? true,
            'allow_redirects' => false, 'security_observability_skip' => true])
            ->connectTimeout(max(1, min(30, (int) $this->config->get('security-observability.delivery.connect_timeout', 3))))
            ->timeout(max(1, min(120, (int) $this->config->get('security-observability.delivery.timeout', 10))))
            ->withHeaders(['Idempotency-Key' => $id, 'Accept' => 'application/json']);
        $token = $this->config->get('security-observability.delivery.token');
        if (is_string($token) && $token !== '') {
            $request = $request->withToken($token, $this->config->get('security-observability.delivery.auth_scheme', 'Bearer'));
        }

        return $request->withBody(json_encode($document, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES | JSON_PRESERVE_ZERO_FRACTION), 'application/json')
            ->send($method, $url);
    }

    public function outcome(Response $response): DeliveryResult
    {
        if ($response->successful()) {
            return DeliveryResult::delivered();
        }
        if (in_array($response->status(), [408, 425, 429], true) || $response->serverError()) {
            return DeliveryResult::retry('http_'.$response->status(), $response->header('Retry-After'));
        }

        return DeliveryResult::quarantine('http_'.$response->status());
    }
}
