<?php

return [
    'enabled' => env('SECURITY_OBSERVABILITY_ENABLED', false),
    'service' => env('SECURITY_OBSERVABILITY_SERVICE', env('APP_NAME', 'laravel')),
    'environment' => env('APP_ENV', 'production'),
    'format' => env('SECURITY_OBSERVABILITY_FORMAT', 'native'),
    'channel' => 'security-observability',
    'output' => env('SECURITY_OBSERVABILITY_OUTPUT', 'php://stderr'),

    /**
     * @var array
     *            Reserved settings: body, query-value, and exception-detail capture are unsupported.
     */
    'capture' => [
        'request_body' => false,
        'response_body' => false,
        'query_values' => false,
        'exception_details' => false,
    ],
    'http' => [
        'accept_correlation' => false,
        'outbound' => true,
        /**
         * @var array
         *            Exact scheme://host[:port], normalized to lower case. Empty means no propagation.
         */
        'propagation_origins' => [],
        'excluded_origins' => [],
    ],
    'queue' => [
        'enabled' => true,
        'excluded_jobs' => [],
    ],
    'security' => [
        'enabled' => true,
        'authentication' => [
            'enabled' => true,
            /**
             * @var array|null
             *                 null accepts all guards that emit Laravel events; custom/token flows may not emit them.
             */
            'guards' => null,
            // PasswordReset and Lockout have no guard; this switch applies independently of guards.
            'include_guardless' => true,
        ],
    ],
    /**
     * @var array
     *            Same connection as business writes enables atomic persistence in their transaction.
     *            An independent connection is needed for observations that must survive rollback.
     */
    'delivery' => [
        'driver' => env('SECURITY_OBSERVABILITY_DRIVER', 'json'),
        'connection' => env('SECURITY_OBSERVABILITY_DB_CONNECTION'),
        'strict_security' => false,
        /**
         * @var string
         *             elasticsearch uses PUT {endpoint}/{event_id}; endpoint must end with /_doc.
         */
        'transport' => env('SECURITY_OBSERVABILITY_TRANSPORT', 'http'),
        'ca_bundle' => env('SECURITY_OBSERVABILITY_CA_BUNDLE'),
        'auth_scheme' => env('SECURITY_OBSERVABILITY_AUTH_SCHEME', 'Bearer'),
        'endpoint' => env('SECURITY_OBSERVABILITY_ENDPOINT'),
        'token' => env('SECURITY_OBSERVABILITY_TOKEN'),
        'max_rows' => 100000,
        'max_bytes' => 104857600,
        'batch_size' => 100,
        'lease_seconds' => 60,
        'connect_timeout' => 3,
        'timeout' => 10,
        'max_attempts' => 10,
        'base_backoff' => 5,
        'max_backoff' => 3600,
        /**
         * @var int
         *          Only delivered records expire; unresolved records continue consuming capacity.
         */
        'retention_seconds' => 604800,
    ],
    'privacy' => [
        'sensitive_keys' => ['password', 'passwd', 'secret', 'token', 'authorization', 'cookie',
            'apikey', 'privatekey', 'cardnumber', 'cvv', 'pin', 'otp', 'bvn'],
        /**
         * @var array
         *            RFC 6901 JSON pointers, e.g. /attributes/customer/email (exact, case-sensitive).
         */
        'redact_paths' => [],
        /**
         * @var array
         *            null allows all attribute keys through redaction; [] excludes every attribute.
         */
        'allowed_attribute_keys' => null,
        'max_string_bytes' => 2048,
        'max_items' => 50,
        'max_depth' => 8,
        'max_nodes' => 1000,
        'max_event_bytes' => 32768,
    ],
];
