# Configuration Guide

Foxy is a highly configurable HTTP proxy with a flexible routing system based on predicates. This document provides a comprehensive guide to all configuration options available.

## Configuration Format

Foxy supports multiple configuration formats:
- JSON (.json)
- TOML (.toml)
- YAML (.yaml, .yml) - requires the `yaml` feature to be enabled

## Configuration Structure

The main configuration structure consists of the following sections:

```json
{
  "server": { ... },      // Server configuration
  "proxy": { ... },       // Proxy configuration
  "routes": [ ... ],      // Route definitions
}
```

## Server Configuration

The `server` section defines the HTTP server settings:

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
  "log_level": "debug"                 // Application log level
}
```

| Property | Type | Default | Description |
|----------|------|---------|-------------|
| `timeout` | Integer | `30` | Request timeout in seconds |
| `global_filters` | Array | `[]` | List of filters to apply to all routes |
| `log_level` | String | `"info"` | Application log level (error, warn, info, debug, trace) |

## Routes Configuration

The `routes` section is an array of route definitions that determine how requests are matched and where they are forwarded:

```json
"routes": [
  {
    "id": "api",                        // Unique identifier
    "target": "http://api.example.com", // Target URL
    "filters": [                        // Filters to apply to this route
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

### Route Target URL Behavior

The `target` URL is used as the base URL for forwarding requests. The final URL is constructed by combining the target URL with the modified path from filters:

```
final_url = target_url + request_path
```

If you need to modify the path before it's appended to the target URL, use the `path_rewrite` filter.

### Route Matching Process

1. Routes are evaluated in priority order (highest priority first)
2. All predicates for a route must match for the route to be selected
3. The first matching route is used
4. If no route matches, a "No route matched" error is returned

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

Filters modify requests and responses as they flow through the proxy. Filters can be defined:

1. Globally for all routes (in `proxy.global_filters`)
2. Per-route (in each route's `filters` array)

Each filter has:
- A type
- Configuration specific to that filter type

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

The **security chain** is an ordered list of *security providers* that can
inspect and/or mutate requests **before** they enter the normal filter
pipeline (and optionally **after** the response is returned).  
Providers are declared in the `proxy.security_chain` array and are executed in
the order they appear.

```jsonc
"proxy": {
  // …existing proxy properties…
  "security_chain": [
    {
      "type": "oidc",        // security-provider type
      "config": { … }        // provider-specific settings
    }
    // additional providers can be added here in future
  ]
}
```

### Execution flow

1. **Pre-security providers** (e.g., JWT validation)
2. **Global & route filters** (pre)
3. **Upstream call**
4. **Global & route filters** (post)
5. **Post-security providers** (if the provider implements `post`)

If a request matches a provider’s *bypass rules* the provider is skipped,
but the rest of the chain continues.

---

## OIDC Provider (`type: "oidc"`)

Authenticates requests that contain an `Authorization: Bearer <jwt>` header
using OpenID Connect discovery and JWKS key retrieval.  
Supports **HS256/384/512, RS256/384/512, PS256/384/512, ES256/384, EdDSA**
algorithms.

```jsonc
{
  "type": "oidc",
  "config": {
    "issuer-uri": "https://id.example.com/.well-known/openid-configuration",
    // Optional – validate the `aud` claim
    "aud": "my-api",
    // Required for HS* algorithms only
    "shared-secret": "base64url-or-hex-encoded-secret",
    // Optional per-provider bypass rules
    "bypass-routes": [
      {
        "methods": ["GET", "POST"],    // HTTP methods (“*” for any)
        "path": "/public/**"           // Glob pattern (see below)
      },
      {
        "methods": ["*"],
        "path": "/swagger-ui/**"
      }
    ]
  }
}
```

| Property | Type | Default | Description |
|----------|------|---------|-------------|
| `issuer-uri` | String | — | OIDC discovery endpoint ending with `/.well-known/openid-configuration`. |
| `aud` | String\|null | `null` | Expected audience (`aud`) claim. Omit to disable audience checking. |
| `shared-secret` | String\|null | `null` | Shared secret for **HS*** algorithms. Ignored for RSA/EC/EdDSA. |
| `bypass-routes` | Array | `[]` | Per-provider list of routes that skip OIDC checks. |

### Bypass Route Rules

Each object inside `bypass-routes` has:

| Field | Type | Description |
|-------|------|-------------|
| `methods` | String[] | List of HTTP methods to match. Use `"*"` to match any method. |
| `path` | String | Glob pattern applied to the request path (`/api/**`, `/static/*.jpg`, etc.). Globbing follows the same semantics as the path predicate. |

> **Tip:** You can have multiple OIDC providers in the chain—for example, one
> for first-party tokens and another for partner identities.

---

### Minimal Example with Security

```jsonc
{
  "server": { "host": "0.0.0.0", "port": 8080 },

  "proxy": {
    "timeout": 30,
    "security_chain": [
      {
        "type": "oidc",
        "config": {
          "issuer-uri": "https://id.example.com/.well-known/openid-configuration",
          "aud": "my-api",
          "bypass-routes": [
            { "methods": ["GET"], "path": "/health" },
            { "methods": ["*"],   "path": "/public/**" }
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

* Any request to `/health` or `/public/**` bypasses JWT validation.
* All other `/api/**` requests must contain a valid bearer token issued by
  `https://id.example.com` with `aud` =`"my-api"`.


## Complete Configuration Example

Here's a complete configuration example:

```json
{
  "server": {
    "host": "127.0.0.1",
    "port": 8080
  },
  "proxy": {
    "timeout": 30,
    "global_filters": [
      {
        "type": "logging",
        "config": {
          "log_request_headers": true,
          "log_request_body": true,
          "log_response_headers": true,
          "log_response_body": true,
          "log_level": "debug",
          "max_body_size": 1024
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
      "filters": [],
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
4. Paths starting with `/resources/` are forwarded to `https://resources.example.com/resources/...` without modification

## Environment Variable Configuration

Foxy also supports configuration via environment variables. The environment variable names are mapped to configuration keys using the following rules:

- Variables must start with the prefix (`FOXY_` by default)
- The prefix is stripped and the remainder is converted to lowercase
- Underscores (`_`) are converted to dots (`.`) for nested access

Examples:
- `FOXY_SERVER_HOST=0.0.0.0` → `server.host`
- `FOXY_PROXY_TIMEOUT=60` → `proxy.timeout`
- `FOXY_PROXY_LOG_LEVEL=debug` → `proxy.log_level`

Complex structures like routes and filters are better configured via files, but simple values can be overridden via environment variables.