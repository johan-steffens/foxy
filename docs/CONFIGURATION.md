# Configuration Guide

Foxy provides a flexible configuration system that supports multiple formats and sources. This guide covers all available configuration options and provides examples to help you get started.

## Configuration Formats

Foxy supports the following configuration formats:
- JSON (`.json`)
- TOML (`.toml`)
- YAML (`.yaml`, `.yml`)

## Configuration Structure

The main configuration consists of three primary sections:

```json
{
  "server": { ... },      // HTTP server settings
  "proxy": { ... },       // Proxy behavior and global filters
  "routes": [ ... ]       // Route definitions and predicates
}
```

## Server Configuration

The `server` section controls the HTTP server settings:

```json
"server": {
  "host": "127.0.0.1",    // Server bind address
  "port": 8080            // Server listen port
}
```

| Property | Type | Default | Description |
|----------|------|---------|-------------|
| `host` | String | `"127.0.0.1"` | Host address to bind the server |
| `port` | Integer | `8080` | Port to listen on |

## Proxy Configuration

The `proxy` section defines general proxy behavior:

```json
"proxy": {
  "timeout": 30,                       // Request timeout in seconds
  "global_filters": [                  // Filters applied to all routes
    {
      "type": "logging",
      "config": {
        "log_request_headers": true,
        "log_level": "debug"
      }
    }
  ],
  "security_chain": [                  // Security providers (optional)
    {
      "type": "oidc",
      "config": { ... }
    }
  ],
  "log_level": "debug"                 // Application log level
}
```

| Property | Type | Default | Description |
|----------|------|---------|-------------|
| `timeout` | Integer | `30` | Request timeout in seconds |
| `global_filters` | Array | `[]` | List of filters to apply to all routes |
| `security_chain` | Array | `[]` | List of security providers to apply |
| `log_level` | String | `"info"` | Application log level (error, warn, info, debug, trace) |

## Routes Configuration

The `routes` section defines how requests are matched and where they are forwarded:

```json
"routes": [
  {
    "id": "api",                        // Unique identifier
    "target": "http://api.example.com", // Target URL
    "filters": [                        // Route-specific filters
      {
        "type": "path_rewrite",
        "config": {
          "pattern": "^/api/(.*)$",
          "replacement": "/v2/$1"
        }
      }
    ],
    "priority": 100,                    // Matching priority
    "predicates": [                     // Request match conditions
      {
        "type_": "path",
        "config": {
          "pattern": "/api/*"
        }
      }
    ]
  }
]
```

| Property | Type | Default | Description |
|----------|------|---------|-------------|
| `id` | String | Required | Unique identifier for the route |
| `target` | String | Required | Base URL to forward matching requests to |
| `filters` | Array | `[]` | List of filters to apply to this route |
| `priority` | Integer | `0` | Priority for route matching (higher values have higher priority) |
| `predicates` | Array | Required | Array of predicates that must all match for this route |

### Route Matching Process

1. Routes are evaluated in priority order (highest priority first)
2. All predicates for a route must match for the route to be selected
3. The first matching route is used
4. If no route matches, a "No route matched" error is returned

### URL Construction

The final URL is constructed by combining the target URL with the request path:

```
final_url = target_url + request_path
```

To modify the path before it's appended to the target URL, use the `path_rewrite` filter.

## Predicates

Predicates determine whether a request matches a route. Each predicate has a type and configuration.

### Path Predicate

Matches the request path against a pattern:

```json
{
  "type_": "path",
  "config": {
    "pattern": "/api/:version/*"
  }
}
```

| Property | Type | Description |
|----------|------|-------------|
| `pattern` | String | Path pattern with support for wildcards and path parameters |

Pattern syntax:
- `*` - Matches any sequence of characters
- `:param` - Matches and captures a path segment
- Regular characters match exactly

Examples:
- `/api/*` - Matches any path starting with "/api/"
- `/users/:id` - Matches paths like "/users/123" with "id" parameter
- `/static/*.jpg` - Matches any jpg files in the static directory

### Method Predicate

Matches the HTTP method:

```json
{
  "type_": "method",
  "config": {
    "methods": ["GET", "POST"]
  }
}
```

| Property | Type | Description |
|----------|------|-------------|
| `methods` | String[] | List of HTTP methods to match (GET, POST, PUT, DELETE, etc.) |

### Header Predicate

Matches request headers:

```json
{
  "type_": "header",
  "config": {
    "headers": {
      "Content-Type": "application/json",
      "X-Required-Header": "value"
    },
    "exact_match": true
  }
}
```

| Property | Type | Default | Description |
|----------|------|---------|-------------|
| `headers` | Object | Required | Map of header names to values to match |
| `exact_match` | Boolean | `false` | Whether values must match exactly (`true`) or just contain the specified value (`false`) |

### Query Predicate

Matches query parameters:

```json
{
  "type_": "query",
  "config": {
    "params": {
      "id": "123",
      "filter": "active"
    },
    "exact_match": true
  }
}
```

| Property | Type | Default | Description |
|----------|------|---------|-------------|
| `params` | Object | Required | Map of query parameter names to values to match |
| `exact_match` | Boolean | `false` | Whether values must match exactly (`true`) or just contain the specified value (`false`) |

## Filters

Filters modify requests and responses as they flow through the proxy. They can be defined:

1. Globally for all routes (in `proxy.global_filters`)
2. Per-route (in each route's `filters` array)

### Filter Definition Format

```json
{
  "type": "filter_type_name",
  "config": {
    // Filter-specific configuration options
  }
}
```

### Filter Application Order

Filters are applied in the following order:
1. Global pre-filters (before forwarding the request)
2. Route-specific pre-filters (before forwarding the request)
3. Request is forwarded to the target
4. Route-specific post-filters (after receiving the response)
5. Global post-filters (after receiving the response)

### Logging Filter

Logs requests and responses:

```json
{
  "type": "logging",
  "config": {
    "log_request_headers": true,
    "log_request_body": false,
    "log_response_headers": true,
    "log_response_body": false,
    "log_level": "debug",
    "max_body_size": 1024
  }
}
```

| Property | Type | Default | Description |
|----------|------|---------|-------------|
| `log_request_headers` | Boolean | `true` | Whether to log request headers |
| `log_request_body` | Boolean | `false` | Whether to log request body |
| `log_response_headers` | Boolean | `true` | Whether to log response headers |
| `log_response_body` | Boolean | `false` | Whether to log response body |
| `log_level` | String | `"trace"` | Log level (error, warn, info, debug, trace) |
| `max_body_size` | Integer | `1024` | Maximum body size in bytes to log |

### Header Filter

Modifies request and response headers:

```json
{
  "type": "header",
  "config": {
    "add_request_headers": {
      "X-Proxy-Version": "Foxy/0.1.0",
      "X-Forwarded-By": "Foxy"
    },
    "remove_request_headers": ["User-Agent"],
    "add_response_headers": {
      "X-Powered-By": "Foxy"
    },
    "remove_response_headers": ["Server"]
  }
}
```

| Property | Type | Default | Description |
|----------|------|---------|-------------|
| `add_request_headers` | Object | `{}` | Headers to add to requests |
| `remove_request_headers` | String[] | `[]` | Headers to remove from requests |
| `add_response_headers` | Object | `{}` | Headers to add to responses |
| `remove_response_headers` | String[] | `[]` | Headers to remove from responses |

### Timeout Filter

Sets a custom timeout for requests:

```json
{
  "type": "timeout",
  "config": {
    "timeout_ms": 5000
  }
}
```

| Property | Type | Default | Description |
|----------|------|---------|-------------|
| `timeout_ms` | Integer | `30000` | Request timeout in milliseconds |

### Path Rewrite Filter

Rewrites request paths based on regex patterns:

```json
{
  "type": "path_rewrite",
  "config": {
    "pattern": "^/api/v1/(.*)",
    "replacement": "/api/v2/$1",
    "rewrite_request": true,
    "rewrite_response": false
  }
}
```

| Property | Type | Default | Description |
|----------|------|---------|-------------|
| `pattern` | String | Required | Regex pattern to match in the path |
| `replacement` | String | Required | Replacement pattern (can use capture groups) |
| `rewrite_request` | Boolean | `true` | Whether to apply on the request path |
| `rewrite_response` | Boolean | `false` | Whether to apply on the response path |

## Security Chain

The security chain is an ordered list of security providers that authenticate requests before they enter the filter pipeline. Providers are defined in the `proxy.security_chain` array:

```json
"proxy": {
  "security_chain": [
    {
      "type": "oidc",
      "config": { ... }
    }
  ]
}
```

### Security Chain Execution Flow

1. Pre-security providers (e.g., JWT validation)
2. Global & route filters (pre)
3. Upstream call
4. Global & route filters (post)
5. Post-security providers (if the provider implements `post`)

If a request matches a provider's bypass rules, the provider is skipped, but the rest of the chain continues.

## OIDC Provider

The OIDC provider authenticates requests with JWT tokens:

```json
{
  "type": "oidc",
  "config": {
    "issuer-uri": "https://id.example.com",
    "jwks-uri": "https://id.example.com/.well-known/jwks.json",
    "aud": "my-api",
    "shared-secret": "base64url-or-hex-encoded-secret",
    "bypass": [
      {
        "methods": ["GET", "POST"],
        "path": "/public/**"
      },
      {
        "methods": ["*"],
        "path": "/swagger-ui/**"
      }
    ]
  }
}
```

### Configuration Properties

| Property | Type | Default | Description |
|----------|------|---------|-------------|
| `issuer-uri` | String | Required | OIDC issuer URI used to validate the `iss` claim in JWTs |
| `jwks-uri` | String | Required | JWKS endpoint URI for retrieving public keys to verify JWT signatures |
| `aud` | String\|null | `null` | Expected audience (`aud`) claim. Omit to disable audience checking |
| `shared-secret` | String\|null | `null` | Shared secret for HS* algorithms. Ignored for RSA/EC/EdDSA |
| `bypass` | Array | `[]` | List of routes that skip OIDC checks |



### Bypass Route Rules

Each object inside `bypass` has:

| Field | Type | Description |
|-------|------|-------------|
| `methods` | String[] | List of HTTP methods to match. Use `"*"` to match any method |
| `path` | String | Glob pattern applied to the request path |

### Common Provider Configurations

**AWS Cognito:**
```json
{
  "type": "oidc",
  "config": {
    "issuer-uri": "https://cognito-idp.us-west-2.amazonaws.com/us-west-2_EXAMPLE",
    "jwks-uri": "https://cognito-idp.us-west-2.amazonaws.com/us-west-2_EXAMPLE/.well-known/jwks.json",
    "aud": "your-app-client-id"
  }
}
```

**Auth0:**
```json
{
  "type": "oidc",
  "config": {
    "issuer-uri": "https://your-domain.auth0.com",
    "jwks-uri": "https://your-domain.auth0.com/.well-known/jwks.json",
    "aud": "your-api-identifier"
  }
}
```

> **Tip:** You can have multiple OIDC providers in the chain—for example, one for first-party tokens and another for partner identities.

## Basic Auth Provider

The Basic Auth provider authenticates requests using the `Authorization` header with `Basic` scheme.

```json
{
  "type": "basic",
  "config": {
    "credentials": [
      "user1:pass1",
      "admin:secure_password"
    ],
    "bypass": [
      {
        "methods": ["GET"],
        "path": "/public/*"
      },
      {
        "methods": ["*"],
        "path": "/health"
      }
    ]
  }
}
```

| Property | Type | Default | Description |
|----------|------|---------|-------------|
| `credentials` | String[] | Required | List of valid `username:password` strings |
| `bypass-routes` | Array | `[]` | List of routes that skip Basic Auth checks |

### Bypass Route Rules

Each object inside `bypass-routes` has:

| Field | Type | Description |
|-------|------|-------------|
| `methods` | String[] | List of HTTP methods to match. Use `"*"` to match any method |
| `path` | String | Glob pattern applied to the request path |

## Environment Variable Configuration

Foxy supports configuration via environment variables using the following mapping rules:

- Variables must start with the prefix (`FOXY_` by default)
- The prefix is stripped and the remainder is converted to lowercase
- Underscores (`_`) are converted to dots (`.`) for nested access

Examples:
- `FOXY_SERVER_HOST=0.0.0.0` → `server.host`
- `FOXY_PROXY_TIMEOUT=60` → `proxy.timeout`
- `FOXY_PROXY_LOG_LEVEL=debug` → `proxy.log_level`

## Configuration Examples

### Basic Proxy with Path Rewriting

```json
{
  "server": {
    "host": "0.0.0.0",
    "port": 8080
  },
  "routes": [
    {
      "id": "api",
      "target": "https://api.example.com",
      "filters": [
        {
          "type": "path_rewrite",
          "config": {
            "pattern": "^/api/(.*)",
            "replacement": "/v2/$1"
          }
        }
      ],
      "predicates": [
        {
          "type_": "path",
          "config": {
            "pattern": "/api/*"
          }
        }
      ]
    }
  ]
}
```

### Proxy with Security

```json
{
  "server": { 
    "host": "0.0.0.0", 
    "port": 8080 
  },
  "proxy": {
    "timeout": 30,
    "security_chain": [
      {
        "type": "oidc",
        "config": {
          "issuer-uri": "https://id.example.com",
          "jwks-uri": "https://id.example.com/.well-known/jwks.json",
          "aud": "my-api",
          "bypass": [
            { "methods": ["GET"], "path": "/health" },
            { "methods": ["*"], "path": "/public/**" }
          ]
        }
      }
    ]
  },
  "routes": [
    {
      "id": "api",
      "target": "https://api.example.com",
      "predicates": [
        { "type_": "path", "config": { "pattern": "/api/**" } }
      ]
    }
  ]
}
```

With this configuration:
* Any request to `/health` or `/public/**` bypasses JWT validation
* All other `/api/**` requests must contain a valid bearer token issued by `https://id.example.com` with `aud` = `"my-api"`

### Advanced Routing Example

```json
{
  "server": {
    "host": "0.0.0.0",
    "port": 8080
  },
  "proxy": {
    "global_filters": [
      {
        "type": "logging",
        "config": {
          "log_request_headers": true,
          "log_level": "debug"
        }
      }
    ]
  },
  "routes": [
    {
      "id": "api-get",
      "target": "https://api.example.com",
      "filters": [
        {
          "type": "path_rewrite",
          "config": {
            "pattern": "^/$",
            "replacement": "/get"
          }
        }
      ],
      "priority": 100,
      "predicates": [
        {
          "type_": "path",
          "config": {
            "pattern": "/"
          }
        },
        {
          "type_": "method",
          "config": {
            "methods": ["GET"]
          }
        }
      ]
    },
    {
      "id": "api-post",
      "target": "https://api.example.com",
      "filters": [
        {
          "type": "path_rewrite",
          "config": {
            "pattern": "^/$",
            "replacement": "/post"
          }
        }
      ],
      "priority": 90,
      "predicates": [
        {
          "type_": "path",
          "config": {
            "pattern": "/"
          }
        },
        {
          "type_": "method",
          "config": {
            "methods": ["POST"]
          }
        }
      ]
    },
    {
      "id": "resources",
      "target": "https://resources.example.com",
      "priority": 50,
      "predicates": [
        {
          "type_": "path",
          "config": {
            "pattern": "/resources/*"
          }
        }
      ]
    }
  ]
}
```

In this example:
1. Global logging filter is applied to all routes
2. The `/` path with GET requests is rewritten to `/get` and forwarded to `https://api.example.com/get`
3. The `/` path with POST requests is rewritten to `/post` and forwarded to `https://api.example.com/post`
4. Paths starting with `/resources/` are forwarded to `https://resources.example.com/resources/...`

## OpenTelemetry Configuration

When enabled as a feature, you can configure OpenTelemetry details as part of the proxy configuration to trace and
exports spans of requests and responses that flow through Foxy.

### Configuration

```json
{
  "proxy": {
    "opentelemetry": {
      "endpoint": "http://otel-collector:4317",
      "service_name": "my-proxy-service",
      "include_headers": true,
      "resource_attributes": {
        "deployment.environment": "production",
        "service.version": "1.2.3",
        "service.instance.id": "i-1234567890abcdef0",
        "cloud.provider": "aws",
        "cloud.region": "us-west-2",
        "host.name": "proxy-pod-abc123"
      },
      "collector_headers": {
        "X-API-Key": "d41000b6-6191-47c5-99f1-7b88b1b97409"
      }
    }
  }
}
```

## Structured Logging

Foxy supports structured logging with JSON output for better integration with log aggregation systems. Configure it in the `proxy.logging` section:

```json
{
  "proxy": {
    "logging": {
      "structured": true,
      "format": "json",
      "level": "info",
      "include_location": true,
      "include_thread_id": true,
      "include_trace_id": true,
      "propagate_trace_id": true,
      "trace_id_header": "X-Trace-ID",
      "static_fields": {
        "app": "foxy-proxy",
        "environment": "production",
        "version": "0.2.16"
      }
    }
  }
}
```

### Structured Logging Configuration Options

| Property | Type | Default | Description |
|----------|------|---------|-------------|
| `structured` | Boolean | `false` | Whether to use structured logging (true) or traditional logging (false) |
| `format` | String | `"terminal"` | Output format: `"terminal"` for human-readable or `"json"` for machine-parseable |
| `level` | String | `"info"` | Log level (trace, debug, info, warn, error, critical) |
| `include_location` | Boolean | `true` | Whether to include source code location (file:line) in logs |
| `include_thread_id` | Boolean | `true` | Whether to include thread ID in logs |
| `include_trace_id` | Boolean | `true` | Whether to include trace ID in logs |
| `propagate_trace_id` | Boolean | `true` | Whether to extract trace IDs from incoming request headers |
| `trace_id_header` | String | `"X-Trace-ID"` | Header name to look for trace IDs in incoming requests |
| `static_fields` | Object | `{}` | Additional static fields to include in all log entries |

### Trace ID Propagation

When `propagate_trace_id` is enabled:

1. Foxy looks for a trace ID in the header specified by `trace_id_header`
2. If found, it uses that trace ID for all logs related to the request
3. If not found, it generates a new UUID as the trace ID
4. The trace ID is added to the response headers

This enables end-to-end tracing across multiple services.

### JSON Log Format

When using JSON format, each log entry is a single-line JSON object with fields like:

```json
{
  "timestamp": "2025-05-24T21:00:00.123Z",
  "level": "INFO",
  "message": "Request received",
  "trace_id": "550e8400-e29b-41d4-a716-446655440000",
  "method": "GET",
  "path": "/api/users",
  "remote_addr": "192.168.1.1:12345",
  "user_agent": "curl/7.79.1",
  "environment": "production",
  "app": "foxy-proxy"
}
```

### Terminal Format

When using terminal format with structured logging, logs are formatted for human readability but still contain the same enriched context:

```
2025-05-24T21:00:00.123Z INFO Request received trace_id=550e8400-e29b-41d4-a716-446655440000 method=GET path=/api/users remote_addr=192.168.1.1:12345 user_agent=curl/7.79.1 environment=production app=foxy-proxy
```

### Integration with OpenTelemetry

When both structured logging and OpenTelemetry are enabled, trace IDs are shared between logs and traces, making it easy to correlate logs with distributed traces in observability platforms.
