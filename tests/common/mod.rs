// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Common test utilities and helpers for Foxy API Gateway tests.

use foxy::config::{ConfigError, ConfigProvider};
use foxy::{HttpMethod, ProxyRequest, ProxyResponse, RequestContext, ResponseContext};
use reqwest::{Body, header::HeaderMap};
use serde_json::Value;
use std::collections::HashMap;
use std::fs;
use std::sync::Arc;
use tempfile::TempDir;
use tokio::sync::RwLock;

/// Test configuration provider for consistent test setups
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct TestConfigProvider {
    values: HashMap<String, Value>,
    name: String,
}

#[allow(dead_code)]
impl TestConfigProvider {
    /// Create a new test config provider with default values
    pub fn new(name: &str) -> Self {
        let mut values = HashMap::new();

        // Default server configuration
        values.insert(
            "server.host".to_string(),
            Value::String("127.0.0.1".to_string()),
        );
        values.insert("server.port".to_string(), Value::Number(8080.into()));
        values.insert("server.health_port".to_string(), Value::Number(8081.into()));

        // Default proxy configuration
        values.insert("proxy.timeout".to_string(), Value::Number(30.into()));
        values.insert(
            "proxy.max_body_size".to_string(),
            Value::Number(1048576.into()),
        ); // 1MB

        // Default logging configuration
        values.insert("proxy.logging.enabled".to_string(), Value::Bool(true));
        values.insert(
            "proxy.logging.level".to_string(),
            Value::String("info".to_string()),
        );

        Self {
            values,
            name: name.to_string(),
        }
    }

    /// Create a new test config provider from a JSON configuration
    pub fn from_json(config: Value) -> Self {
        let mut values = HashMap::new();

        // Flatten the JSON config into dot-notation keys
        Self::flatten_json(&config, "", &mut values);

        Self {
            values,
            name: "json-config".to_string(),
        }
    }

    /// Helper function to flatten JSON into dot-notation keys
    fn flatten_json(value: &Value, prefix: &str, values: &mut HashMap<String, Value>) {
        match value {
            Value::Object(obj) => {
                for (key, val) in obj {
                    let new_key = if prefix.is_empty() {
                        key.clone()
                    } else {
                        format!("{prefix}.{key}")
                    };

                    match val {
                        Value::Object(_) => {
                            Self::flatten_json(val, &new_key, values);
                        }
                        _ => {
                            values.insert(new_key, val.clone());
                        }
                    }
                }
            }
            _ => {
                values.insert(prefix.to_string(), value.clone());
            }
        }
    }

    /// Add a configuration value
    pub fn with_value<T: Into<Value>>(mut self, key: &str, value: T) -> Self {
        self.values.insert(key.to_string(), value.into());
        self
    }

    /// Add multiple configuration values
    pub fn with_values(mut self, values: HashMap<String, Value>) -> Self {
        self.values.extend(values);
        self
    }

    /// Create a test config with routes
    pub fn with_routes(mut self, routes: Vec<TestRoute>) -> Self {
        let routes_value: Vec<Value> = routes.into_iter().map(|r| r.into()).collect();
        self.values
            .insert("routes".to_string(), Value::Array(routes_value));
        self
    }

    /// Debug method to print the configuration
    pub fn debug_print(&self) {
        println!("TestConfigProvider values:");
        for (key, value) in &self.values {
            println!(
                "  {}: {}",
                key,
                serde_json::to_string_pretty(value).unwrap_or_else(|_| "invalid json".to_string())
            );
        }
    }

    /// Debug method to print the routes configuration specifically
    pub fn debug_print_routes(&self) {
        if let Some(routes) = self.values.get("routes") {
            println!("Routes configuration:");
            println!(
                "{}",
                serde_json::to_string_pretty(routes).unwrap_or_else(|_| "invalid json".to_string())
            );
        } else {
            println!("No routes found in configuration");
        }
    }
}

impl TestConfigProvider {
    /// Get a nested value from the configuration by a dot-separated key path.
    fn get_nested_value(&self, key_path: &str) -> Option<Value> {
        // First check if we have the exact key
        if let Some(value) = self.values.get(key_path) {
            return Some(value.clone());
        }

        // Try to build nested object from individual keys
        let prefix = format!("{key_path}.");
        let mut nested_obj = serde_json::Map::new();

        for (key, value) in &self.values {
            if key.starts_with(&prefix) {
                let suffix = &key[prefix.len()..];
                if !suffix.contains('.') {
                    // This is a direct child
                    nested_obj.insert(suffix.to_string(), value.clone());
                }
            }
        }

        if !nested_obj.is_empty() {
            Some(Value::Object(nested_obj))
        } else {
            None
        }
    }
}

impl ConfigProvider for TestConfigProvider {
    fn has(&self, key: &str) -> bool {
        self.get_nested_value(key).is_some()
    }

    fn provider_name(&self) -> &str {
        &self.name
    }

    fn get_raw(&self, key: &str) -> Result<Option<Value>, ConfigError> {
        Ok(self.get_nested_value(key))
    }
}

/// Helper struct for creating test routes
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct TestRoute {
    pub id: String,
    pub predicates: Vec<TestPredicate>,
    pub target: String,
    pub filters: Vec<TestFilter>,
    pub raw_filters: Vec<serde_json::Value>,
}

#[allow(dead_code)]
impl TestRoute {
    pub fn new(target: &str) -> Self {
        use std::sync::atomic::{AtomicUsize, Ordering};
        static COUNTER: AtomicUsize = AtomicUsize::new(0);
        let id = format!("test-route-{}", COUNTER.fetch_add(1, Ordering::SeqCst));

        Self {
            id,
            predicates: Vec::new(),
            target: target.to_string(),
            filters: Vec::new(),
            raw_filters: Vec::new(),
        }
    }

    pub fn with_path(mut self, pattern: &str) -> Self {
        self.predicates
            .push(TestPredicate::Path(pattern.to_string()));
        self
    }

    pub fn with_method(mut self, method: HttpMethod) -> Self {
        self.predicates.push(TestPredicate::Method(vec![method]));
        self
    }

    pub fn with_header(mut self, name: &str, value: &str) -> Self {
        self.predicates
            .push(TestPredicate::Header(name.to_string(), value.to_string()));
        self
    }

    pub fn with_filter(mut self, filter: TestFilter) -> Self {
        self.filters.push(filter);
        self
    }

    /// Add a raw filter configuration (for testing custom filters)
    pub fn with_raw_filter(mut self, filter_type: &str, config: serde_json::Value) -> Self {
        // Create a custom TestFilter variant that holds raw configuration
        // We'll add this to the filters list as a JSON object directly
        self.raw_filters.push(serde_json::json!({
            "type": filter_type,
            "config": config
        }));
        self
    }
}

impl From<TestRoute> for Value {
    fn from(val: TestRoute) -> Self {
        let mut route = serde_json::Map::new();
        route.insert("id".to_string(), Value::String(val.id));
        route.insert("target".to_string(), Value::String(val.target));

        if !val.predicates.is_empty() {
            let predicates: Vec<Value> = val.predicates.into_iter().map(|p| p.into()).collect();
            route.insert("predicates".to_string(), Value::Array(predicates));
        }

        if !val.filters.is_empty() || !val.raw_filters.is_empty() {
            let mut all_filters: Vec<Value> = val.filters.into_iter().map(|f| f.into()).collect();
            all_filters.extend(val.raw_filters);
            route.insert("filters".to_string(), Value::Array(all_filters));
        }

        // Add default priority
        route.insert("priority".to_string(), Value::Number(0.into()));

        Value::Object(route)
    }
}

/// Test predicate configurations
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub enum TestPredicate {
    Path(String),
    Method(Vec<HttpMethod>),
    Header(String, String),
    Query(String, String),
}

impl From<TestPredicate> for Value {
    fn from(val: TestPredicate) -> Self {
        match val {
            TestPredicate::Path(pattern) => {
                let mut pred = serde_json::Map::new();
                pred.insert("type_".to_string(), Value::String("path".to_string()));
                let mut config = serde_json::Map::new();
                config.insert("pattern".to_string(), Value::String(pattern));
                pred.insert("config".to_string(), Value::Object(config));
                Value::Object(pred)
            }
            TestPredicate::Method(methods) => {
                let mut pred = serde_json::Map::new();
                pred.insert("type_".to_string(), Value::String("method".to_string()));
                let mut config = serde_json::Map::new();
                let method_strings: Vec<Value> = methods
                    .into_iter()
                    .map(|m| Value::String(m.to_string()))
                    .collect();
                config.insert("methods".to_string(), Value::Array(method_strings));
                pred.insert("config".to_string(), Value::Object(config));
                Value::Object(pred)
            }
            TestPredicate::Header(name, value) => {
                let mut pred = serde_json::Map::new();
                pred.insert("type_".to_string(), Value::String("header".to_string()));
                let mut config = serde_json::Map::new();
                let mut headers = serde_json::Map::new();
                headers.insert(name, Value::String(value));
                config.insert("headers".to_string(), Value::Object(headers));
                config.insert("exact_match".to_string(), Value::Bool(true));
                pred.insert("config".to_string(), Value::Object(config));
                Value::Object(pred)
            }
            TestPredicate::Query(name, value) => {
                let mut pred = serde_json::Map::new();
                pred.insert("type_".to_string(), Value::String("query".to_string()));
                let mut config = serde_json::Map::new();
                let mut params = serde_json::Map::new();
                params.insert(name, Value::String(value));
                config.insert("params".to_string(), Value::Object(params));
                config.insert("exact_match".to_string(), Value::Bool(true));
                pred.insert("config".to_string(), Value::Object(config));
                Value::Object(pred)
            }
        }
    }
}

/// Test filter configurations
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub enum TestFilter {
    Logging {
        log_bodies: bool,
    },
    Header {
        add: HashMap<String, String>,
        remove: Vec<String>,
    },
    Timeout {
        timeout_ms: u64,
    },
    PathRewrite {
        pattern: String,
        replacement: String,
    },
}

impl From<TestFilter> for Value {
    fn from(val: TestFilter) -> Self {
        match val {
            TestFilter::Logging { log_bodies } => {
                let mut filter = serde_json::Map::new();
                filter.insert("type".to_string(), Value::String("logging".to_string()));
                let mut config = serde_json::Map::new();
                config.insert("log_request_body".to_string(), Value::Bool(log_bodies));
                config.insert("log_response_body".to_string(), Value::Bool(log_bodies));
                filter.insert("config".to_string(), Value::Object(config));
                Value::Object(filter)
            }
            TestFilter::Header { add, remove } => {
                let mut filter = serde_json::Map::new();
                filter.insert("type".to_string(), Value::String("header".to_string()));
                let mut config = serde_json::Map::new();

                let add_headers: serde_json::Map<String, Value> = add
                    .into_iter()
                    .map(|(k, v)| (k, Value::String(v)))
                    .collect();
                config.insert(
                    "add_request_headers".to_string(),
                    Value::Object(add_headers),
                );

                let remove_headers: Vec<Value> = remove.into_iter().map(Value::String).collect();
                config.insert(
                    "remove_request_headers".to_string(),
                    Value::Array(remove_headers),
                );

                filter.insert("config".to_string(), Value::Object(config));
                Value::Object(filter)
            }
            TestFilter::Timeout { timeout_ms } => {
                let mut filter = serde_json::Map::new();
                filter.insert("type".to_string(), Value::String("timeout".to_string()));
                let mut config = serde_json::Map::new();
                config.insert("timeout_ms".to_string(), Value::Number(timeout_ms.into()));
                filter.insert("config".to_string(), Value::Object(config));
                Value::Object(filter)
            }
            TestFilter::PathRewrite {
                pattern,
                replacement,
            } => {
                let mut filter = serde_json::Map::new();
                filter.insert(
                    "type".to_string(),
                    Value::String("path_rewrite".to_string()),
                );
                let mut config = serde_json::Map::new();
                config.insert("pattern".to_string(), Value::String(pattern));
                config.insert("replacement".to_string(), Value::String(replacement));
                config.insert("rewrite_request".to_string(), Value::Bool(true));
                filter.insert("config".to_string(), Value::Object(config));
                Value::Object(filter)
            }
        }
    }
}

/// Create a test request with common defaults
#[allow(dead_code)]
pub fn create_test_request(
    method: HttpMethod,
    path: &str,
    query: Option<&str>,
    headers: Vec<(&str, &str)>,
    body: Vec<u8>,
) -> ProxyRequest {
    let mut header_map = HeaderMap::new();
    for (name, value) in headers {
        header_map.insert(
            reqwest::header::HeaderName::from_bytes(name.as_bytes()).unwrap(),
            reqwest::header::HeaderValue::from_str(value).unwrap(),
        );
    }

    ProxyRequest {
        method,
        path: path.to_string(),
        query: query.map(|q| q.to_string()),
        headers: header_map,
        body: Body::from(body),
        context: Arc::new(RwLock::new(RequestContext::default())),
        custom_target: Some("http://test.example.com".to_string()),
    }
}

/// Create a test response with common defaults
#[allow(dead_code)]
pub fn create_test_response(
    status: u16,
    headers: Vec<(&str, &str)>,
    body: Vec<u8>,
) -> ProxyResponse {
    let mut header_map = HeaderMap::new();
    for (name, value) in headers {
        header_map.insert(
            reqwest::header::HeaderName::from_bytes(name.as_bytes()).unwrap(),
            reqwest::header::HeaderValue::from_str(value).unwrap(),
        );
    }

    ProxyResponse {
        status,
        headers: header_map,
        body: Body::from(body),
        context: Arc::new(RwLock::new(ResponseContext::default())),
    }
}

/// Create a temporary configuration file for testing
#[allow(dead_code)]
pub fn create_temp_config_file(
    content: &str,
    format: &str,
) -> Result<(TempDir, String), std::io::Error> {
    let temp_dir = TempDir::new()?;
    let file_name = format!("test_config.{format}");
    let file_path = temp_dir.path().join(&file_name);

    fs::write(&file_path, content)?;

    Ok((temp_dir, file_path.to_string_lossy().to_string()))
}

/// Initialize test logging (call once per test module)
pub fn init_test_logging() {
    // Don't initialize logging in tests - let the library handle it
    // This prevents conflicts with the library's logging initialization
}
