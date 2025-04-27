# Configuration Guide

Foxy is a highly configurable HTTP proxy with a flexible routing system based on predicates. This document provides a comprehensive guide to all configuration options available.

## Configuration Format

Foxy supports multiple configuration formats:
- JSON (.json)
- TOML (.toml)
- YAML (.yaml, .yml) - requires the `yaml` feature to be enabled

If these don't suffice, you can implement a custom configuration provider to suit your needs.

## Configuration Structure

The main configuration structure consists of the following sections:

```json
{
  "server": { ... },      // Server configuration
  "proxy": { ... },       // Proxy configuration
  "routes": [ ... ],      // Route definitions
  "filters": { ... }      // Filter definitions
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
  "timeout": 30
}
```

| Property | Type | Default | Description |
|----------|------|---------|-------------|
| `timeout` | Integer | `30` | Request timeout in seconds |

## Routes Configuration

The `routes` section is an array of route definitions that determine how requests are matched and where they are forwarded:

```json
"routes": [
  {
    "id": "api",                      // Unique identifier
    "target": "http://api-service.com", // Target URL
    "filters": ["logging"],           // Filters to apply
    "priority": 100,                  // Matching priority
    "predicates": [                   // Request match conditions
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
| `filters` | String[] | `[]` | List of filter IDs to apply to this route |
| `priority` | Integer | `0` | Priority for route matching (higher values have higher priority) |
| `predicates` | Predicate[] | Required | Array of predicates that must all match for this route |

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

Filters modify requests and responses as they flow through the proxy. The `filters` section maps filter IDs to filter configurations:

```json
"filters": {
  "logging": {
    "type": "logging",
    "config": {
      "log_request_headers": true,
      "log_request_body": false,
      "log_level": "debug"
    }
  }
}
```

Each filter has:
- An ID (used in route `filters` array)
- A type
- Configuration specific to that filter type

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

## Complete Configuration Example

Here's a complete configuration example that demonstrates most features:

```json
{
  "server": {
    "host": "127.0.0.1",
    "port": 8080
  },
  "proxy": {
    "timeout": 30
  },
  "routes": [
    {
      "id": "api-get",
      "target": "http://api-service.com",
      "filters": ["logging"],
      "priority": 100,
      "predicates": [
        {
          "type_": "path",
          "config": {
            "pattern": "/api/*"
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
      "target": "http://api-write-service.com",
      "filters": ["logging", "header"],
      "priority": 90,
      "predicates": [
        {
          "type_": "path",
          "config": {
            "pattern": "/api/*"
          }
        },
        {
          "type_": "method",
          "config": {
            "methods": ["POST", "PUT", "DELETE"]
          }
        }
      ]
    },
    {
      "id": "admin",
      "target": "http://admin-service.com",
      "filters": ["logging"],
      "priority": 80,
      "predicates": [
        {
          "type_": "path",
          "config": {
            "pattern": "/admin/*"
          }
        },
        {
          "type_": "header",
          "config": {
            "headers": {
              "Authorization": "Bearer "
            },
            "exact_match": false
          }
        }
      ]
    },
    {
      "id": "static",
      "target": "http://static-service.com",
      "filters": [],
      "priority": 70,
      "predicates": [
        {
          "type_": "path",
          "config": {
            "pattern": "/static/*"
          }
        }
      ]
    },
    {
      "id": "search",
      "target": "http://search-service.com",
      "filters": ["logging"],
      "priority": 60,
      "predicates": [
        {
          "type_": "path",
          "config": {
            "pattern": "/search"
          }
        },
        {
          "type_": "query",
          "config": {
            "params": {
              "q": ""
            },
            "exact_match": false
          }
        }
      ]
    },
    {
      "id": "default",
      "target": "http://default-service.com",
      "filters": [],
      "priority": 0,
      "predicates": [
        {
          "type_": "path",
          "config": {
            "pattern": "/*"
          }
        }
      ]
    }
  ],
  "filters": {
    "logging": {
      "type": "logging",
      "config": {
        "log_request_headers": true,
        "log_request_body": false,
        "log_response_headers": true,
        "log_response_body": false,
        "log_level": "debug",
        "max_body_size": 1024
      }
    },
    "header": {
      "type": "header",
      "config": {
        "add_request_headers": {
          "X-Proxy-Version": "Foxy/0.1.0"
        },
        "add_response_headers": {
          "X-Powered-By": "Foxy"
        }
      }
    },
    "timeout": {
      "type": "timeout",
      "config": {
        "timeout_ms": 5000
      }
    }
  }
}
```

## Environment Variable Configuration

Foxy also supports configuration via environment variables. The environment variable names are mapped to configuration keys using the following rules:

- Variables must start with the prefix (`FOXY_` by default)
- The prefix is stripped and the remainder is converted to lowercase
- Underscores (`_`) are converted to dots (`.`) for nested access

Examples:
- `FOXY_SERVER_HOST=0.0.0.0` → `server.host`
- `FOXY_PROXY_TIMEOUT=60` → `proxy.timeout`

Complex structures like routes and filters are better configured via files, but simple values can be overridden via environment variables.