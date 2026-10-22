<?php

declare(strict_types=1);

namespace Kater\SecurityObservability\Privacy;

use Illuminate\Contracts\Config\Repository;
use Kater\SecurityObservability\Contracts\Redactor;

final class PrivacyPipeline implements Redactor
{
    public function __construct(private Repository $config) {}

    public function redact(array $data): array
    {
        $budget = max(1, min(10000, (int) $this->config->get('security-observability.privacy.max_nodes', 1000)));

        return $this->walk($data, [], 0, $budget);
    }

    private function walk(array $data, array $path, int $depth, int &$budget): array
    {
        $result = [];
        $maxItems = max(1, min(1000, (int) $this->config->get('security-observability.privacy.max_items', 50)));
        $maxDepth = max(1, min(32, (int) $this->config->get('security-observability.privacy.max_depth', 8)));
        $identity = count($path) === 1 && in_array($path[0], ['actor', 'target', 'tenant'], true);
        $visited = 0;
        foreach ($data as $key => $value) {
            $identityField = $identity && in_array((string) $key, ['type', 'id'], true);
            if (($depth > 0 && ! $identityField && $budget-- <= 0) || ++$visited > ($depth === 0 ? max(32, $maxItems) : ($identity ? max(2, $maxItems) : $maxItems))) {
                break;
            }
            $key = (string) $key;
            // Drop overlong or invalid keys rather than truncate into collisions or bypass exact paths.
            if (strlen($key) > 256 || preg_match('//u', $key) !== 1) {
                continue;
            }
            $next = [...$path, $key];
            $pointer = '/'.implode('/', array_map(static fn ($p) => str_replace(['~', '/'], ['~0', '~1'], $p), $next));
            $allow = $this->config->get('security-observability.privacy.allowed_attribute_keys');
            if ($path === ['attributes'] && is_array($allow) && ! in_array($key, $allow, true)) {
                continue;
            }
            $normalized = strtolower(preg_replace('/[^a-zA-Z0-9]/', '', $key));
            $sensitive = false;
            foreach ($this->config->get('security-observability.privacy.sensitive_keys', []) as $fragment) {
                if (is_string($fragment) && $fragment !== '' && str_contains($normalized, strtolower(preg_replace('/[^a-zA-Z0-9]/', '', $fragment)))) {
                    $sensitive = true;
                    break;
                }
            }
            if ($sensitive || in_array($pointer, $this->config->get('security-observability.privacy.redact_paths', []), true)) {
                $result[$key] = '[REDACTED]';
            } elseif (is_array($value)) {
                $result[$key] = $depth >= $maxDepth ? '[DEPTH_LIMIT]' : $this->walk($value, $next, $depth + 1, $budget);
            } elseif (is_string($value)) {
                // Attribute limits must not truncate typed identifiers into a different identity.
                $minimum = $identityField ? ($key === 'id' ? 256 : 64) : ($depth === 0 ? 128 : 16);
                $result[$key] = $this->string($value, $minimum);
            } elseif ($value === null || is_bool($value) || is_int($value)) {
                $result[$key] = $value;
            } elseif (is_float($value) && is_finite($value)) {
                $result[$key] = $value;
            } else {
                // Never call __toString(), jsonSerialize(), or traverse arbitrary objects.
                $result[$key] = '[UNSUPPORTED]';
            }
        }

        return $result;
    }

    private function string(string $value, int $minimum): string
    {
        $max = max($minimum, min(16384, (int) $this->config->get('security-observability.privacy.max_string_bytes', 2048)));
        $value = substr($value, 0, $max);

        // Substitute malformed UTF-8; JSON encoding also escapes control characters.
        return mb_strcut(json_decode(json_encode($value, JSON_INVALID_UTF8_SUBSTITUTE | JSON_THROW_ON_ERROR), true, flags: JSON_THROW_ON_ERROR), 0, $max, 'UTF-8');
    }
}
