# Extension Guide

This guide provides examples for using Foxy's trait-based system to create custom `Filters`, `Predicates`, and `SecurityProviders`. It covers implementing the necessary traits, registering your components, and enabling them through the proxy configuration.

## Custom Filters

Filters allow you to inspect and modify HTTP requests and responses as they pass through the proxy.

### Example: `AddCorrelationIdFilter`

Let's create a filter that adds a unique `X-Correlation-ID` header to every incoming request.

`src/my_filters.rs`:
```rust
use foxy::{Filter, FilterType, ProxyRequest, ProxyError};
use async_trait::async_trait;
use uuid::Uuid;

#[derive(Debug)]
pub struct AddCorrelationIdFilter;

impl AddCorrelationIdFilter {
    // The constructor receives the JSON config block from your foxy.json/yaml.
    // We don't need any config for this simple filter.
    pub fn new(_config: serde_json::Value) -> Result<Self, ProxyError> {
        Ok(Self)
    }
}

#[async_trait]
impl Filter for AddCorrelationIdFilter {
    // This is a pre-filter, so it runs before the request is sent upstream.
    fn filter_type(&self) -> FilterType {
        FilterType::Pre
    }

    // The name used in the configuration file.
    fn name(&self) -> &str {
        "add_correlation_id"
    }

    async fn pre_filter(&self, mut request: ProxyRequest) -> Result<ProxyRequest, ProxyError> {
        let correlation_id = Uuid::new_v4().to_string();
        
        // Add the header to the request.
        request.headers.insert(
            "X-Correlation-ID",
            correlation_id.parse().unwrap(),
        );
        
        println!("Added X-Correlation-ID: {}", correlation_id);

        Ok(request)
    }
}
```

### Registration and Usage

Register your filter in main.rs before building the Foxy instance.

`src/main.rs`:
```rust
use foxy::Foxy;
use foxy::filters::register_filter;
use std::sync::Arc;
// Import your custom filter
mod my_filters;
use my_filters::AddCorrelationIdFilter;

#[tokio::main]
async fn main() {
    // 1. Register the filter
    register_filter("add_correlation_id", |config| {
        Ok(Arc::new(AddCorrelationIdFilter::new(config)?))
    });

    // 2. Build Foxy as usual
    let foxy = Foxy::loader()
        .with_config_file("config.json")
        .build().await
        .unwrap();

    foxy.start().await.unwrap();
}
```

Now, you can use add_correlation_id in your configuration.

`config.json`:
```json
{
  "proxy": {
    "global_filters": [
      {
        "type": "add_correlation_id",
        "config": {}
      }
    ]
  },
  "routes": [
    // ... your routes
  ]
}
```

## Custom Predicates

Predicates are used to create custom routing rules. A route is selected only if all of its predicates match the incoming request.

### Example: UserAgentPredicate

Here's a predicate that matches requests from a specific user agent.

`src/my_predicates.rs`:
```rust
use foxy::{Predicate, ProxyRequest, ProxyError};
use async_trait::async_trait;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct UserAgentPredicateConfig {
    pattern: String,
}

#[derive(Debug)]
pub struct UserAgentPredicate {
    pattern: String,
}

impl UserAgentPredicate {
    pub fn new(config: serde_json::Value) -> Result<Self, ProxyError> {
        let config: UserAgentPredicateConfig = serde_json::from_value(config)
            .map_err(|e| ProxyError::ConfigError(e.to_string()))?;
        Ok(Self { pattern: config.pattern })
    }
}

#[async_trait]
impl Predicate for UserAgentPredicate {
    fn predicate_type(&self) -> &str {
        "user_agent"
    }

    async fn matches(&self, request: &ProxyRequest) -> bool {
        request.headers
            .get("User-Agent")
            .and_then(|v| v.to_str().ok())
            .map_or(false, |ua| ua.contains(&self.pattern))
    }
}
```

### Registration and Usage

`src/main.rs`:
```rust
use foxy::Foxy;
use foxy::router::register_predicate;
use std::sync::Arc;
// Import your custom predicate
mod my_predicates;
use my_predicates::UserAgentPredicate;

#[tokio::main]
async fn main() {
    // 1. Register the predicate
    register_predicate("user_agent", |config| {
        Ok(Arc::new(UserAgentPredicate::new(config)?))
    });

    // 2. Build Foxy
    // ...
}
```

`config.json`:
```json
{
  "routes": [
    {
      "id": "mobile-api-route",
      "target": "http://mobile-backend:8080",
      "priority": 100,
      "predicates": [
        {
          "type": "path",
          "config": { "pattern": "/api/mobile/*" }
        },
        {
          "type": "user_agent",
          "config": {
            "pattern": "FoxyMobileClient"
          }
        }
      ]
    }
  ]
}
```

## Custom Security Providers

Security providers are used to implement custom authentication and authorization logic, such as API key validation, custom JWT schemes, or HMAC signature verification.

### Example: ApiKeyProvider

This provider checks for a valid X-API-Key header.

`src/my_security.rs`:
```rust
use foxy::{SecurityProvider, SecurityStage, ProxyRequest, ProxyError};
use async_trait::async_trait;
use serde::Deserialize;
use std::collections::HashSet;
use std::future::Future;
use std::pin::Pin;

#[derive(Debug, Deserialize)]
struct ApiKeyProviderConfig {
    valid_keys: Vec<String>,
}

#[derive(Debug)]
pub struct ApiKeyProvider {
    valid_keys: HashSet<String>,
}

impl ApiKeyProvider {
    // Security Provider constructors are async because some, like OIDC,
    // may need to perform network requests for discovery.
    pub fn new(config: serde_json::Value) -> Pin<Box<dyn Future<Output = Result<Self, ProxyError>> + Send>> {
        Box::pin(async {
            let config: ApiKeyProviderConfig = serde_json::from_value(config)
                .map_err(|e| ProxyError::ConfigError(e.to_string()))?;

            let valid_keys = config.valid_keys.into_iter().collect();
            Ok(Self { valid_keys })
        })
    }
}

#[async_trait]
impl SecurityProvider for ApiKeyProvider {
    fn name(&self) -> &str {
        "api_key"
    }

    fn stage(&self) -> SecurityStage {
        SecurityStage::Pre
    }

    async fn pre(&self, request: ProxyRequest) -> Result<ProxyRequest, ProxyError> {
        if let Some(key) = request.headers.get("X-API-Key").and_then(|v| v.to_str().ok()) {
            if self.valid_keys.contains(key) {
                // Key is valid, allow the request to proceed.
                return Ok(request);
            }
        }
        // Key is missing or invalid.
        Err(ProxyError::SecurityError("Invalid or missing API Key".to_string()))
    }
}
```

### Registration and Usage

`src/main.rs`:
```rust
use foxy::Foxy;
use foxy::security::register_security_provider;
use std::sync::Arc;
// Import your custom provider
mod my_security;
use my_security::ApiKeyProvider;

#[tokio::main]
async fn main() {
    // 1. Register the security provider
    register_security_provider("api_key", |config| {
        Box::pin(async {
            let provider = ApiKeyProvider::new(config).await?;
            Ok(Arc::new(provider) as Arc<dyn foxy::SecurityProvider>)
        })
    });
    
    // 2. Build Foxy
    // ...
}
```

`config.json`:
```json
{
  "proxy": {
    "security_chain": [
      {
        "type": "api_key",
        "config": {
          "valid_keys": [
            "secret-key-1",
            "secret-key-2"
          ]
        }
      }
    ]
  },
  "routes": [
    // ... your routes
  ]
}
```