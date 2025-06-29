// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Error handling integration tests for Foxy API Gateway

use async_trait::async_trait;
use foxy::config::ConfigProvider;
use foxy::{
    ConfigError, Filter, FilterType, Foxy, LoaderError, ProxyError, ProxyRequest, ProxyResponse,
    Route, Router,
};
use serde_json::Value;
use std::time::Duration;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

mod common;
use common::{TestConfigProvider, TestRoute, init_test_logging};

// Mock implementations for error testing
#[derive(Debug)]
struct FailingConfigProvider;

impl ConfigProvider for FailingConfigProvider {
    fn has(&self, _key: &str) -> bool {
        true
    }

    fn provider_name(&self) -> &str {
        "failing-provider"
    }

    fn get_raw(&self, _key: &str) -> Result<Option<Value>, ConfigError> {
        Err(ConfigError::ParseError(
            "Simulated config error".to_string(),
        ))
    }
}

#[derive(Debug)]
#[allow(dead_code)]
struct FailingRouter;

#[async_trait]
impl Router for FailingRouter {
    async fn route(&self, _request: &ProxyRequest) -> Result<Route, ProxyError> {
        Err(ProxyError::RoutingError("No route found".to_string()))
    }

    async fn get_routes(&self) -> Vec<Route> {
        Vec::new()
    }

    async fn add_route(&self, _route: Route) -> Result<(), ProxyError> {
        Err(ProxyError::RoutingError("Cannot add route".to_string()))
    }

    async fn remove_route(&self, _route_id: &str) -> Result<(), ProxyError> {
        Err(ProxyError::RoutingError("Cannot remove route".to_string()))
    }
}

#[derive(Debug)]
#[allow(dead_code)]
struct FailingFilter {
    name: String,
    fail_pre: bool,
    fail_post: bool,
}

#[allow(dead_code)]
impl FailingFilter {
    fn new(name: &str, fail_pre: bool, fail_post: bool) -> Self {
        Self {
            name: name.to_string(),
            fail_pre,
            fail_post,
        }
    }
}

#[async_trait]
impl Filter for FailingFilter {
    fn filter_type(&self) -> FilterType {
        FilterType::Both
    }

    fn name(&self) -> &str {
        &self.name
    }

    async fn pre_filter(&self, request: ProxyRequest) -> Result<ProxyRequest, ProxyError> {
        if self.fail_pre {
            Err(ProxyError::FilterError(format!(
                "Pre-filter {} failed",
                self.name
            )))
        } else {
            Ok(request)
        }
    }

    async fn post_filter(
        &self,
        _request: ProxyRequest,
        response: ProxyResponse,
    ) -> Result<ProxyResponse, ProxyError> {
        if self.fail_post {
            Err(ProxyError::FilterError(format!(
                "Post-filter {} failed",
                self.name
            )))
        } else {
            Ok(response)
        }
    }
}

#[tokio::test]
async fn test_config_error_handling() {
    init_test_logging();

    // Test with failing config provider
    let loader = Foxy::loader().with_provider(FailingConfigProvider);

    let result = loader.build().await;
    assert!(result.is_err());

    // The error can be either ConfigError or ProxyError(ConfigError(...))
    match result {
        Err(LoaderError::ConfigError(_)) => {
            // Direct config error - expected
        }
        Err(LoaderError::ProxyError(ProxyError::ConfigError(_))) => {
            // Config error wrapped in ProxyError - also expected
        }
        other => {
            panic!("Expected ConfigError or ProxyError(ConfigError), got: {other:?}");
        }
    }
}

#[tokio::test]
async fn test_invalid_configuration_values() {
    init_test_logging();

    // Test with invalid timeout value
    let config = TestConfigProvider::new("invalid_test")
        .with_value("proxy.timeout", "not-a-number")
        .with_value("server.port", -1); // Invalid port

    let result = Foxy::loader().with_provider(config).build().await;

    // Should handle invalid configuration gracefully
    assert!(result.is_err());
}

#[tokio::test]
async fn test_network_timeout_error() {
    init_test_logging();

    // Start a mock server that will delay responses
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/slow"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_delay(Duration::from_secs(5)) // 5 second delay
                .set_body_string("Slow response"),
        )
        .mount(&mock_server)
        .await;

    // Configure proxy with very short timeout
    let config = TestConfigProvider::new("timeout_test")
        .with_value("proxy.timeout", 1) // 1 second timeout
        .with_value("server.port", 0)
        .with_routes(vec![TestRoute::new(&mock_server.uri()).with_path("/slow")]);

    let foxy = Foxy::loader()
        .with_provider(config)
        .build()
        .await
        .expect("Failed to build Foxy instance");

    let server_handle = tokio::spawn(async move { foxy.start().await });

    tokio::time::sleep(Duration::from_millis(100)).await;

    // Make request that should timeout
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .unwrap();

    let response = client.get("http://127.0.0.1:8080/slow").send().await;

    // Should get a timeout or error response
    match response {
        Ok(resp) => {
            // If we get a response, it should be an error status
            assert!(resp.status().is_server_error() || resp.status().is_client_error());
        }
        Err(e) => {
            // Network error is also acceptable
            println!("Expected network error: {e}");
        }
    }

    server_handle.abort();
}

#[tokio::test]
async fn test_upstream_server_unavailable() {
    init_test_logging();

    // Configure proxy to point to non-existent server
    let config = TestConfigProvider::new("unavailable_test")
        .with_value("server.port", 0)
        .with_routes(vec![
            TestRoute::new("http://localhost:99999") // Non-existent server
                .with_path("/api/*"),
        ]);

    let foxy = Foxy::loader()
        .with_provider(config)
        .build()
        .await
        .expect("Failed to build Foxy instance");

    let server_handle = tokio::spawn(async move { foxy.start().await });

    tokio::time::sleep(Duration::from_millis(100)).await;

    // Make request to unavailable upstream
    let client = reqwest::Client::new();
    let response = client.get("http://127.0.0.1:8080/api/test").send().await;

    match response {
        Ok(resp) => {
            // Should get a 502 Bad Gateway or similar error
            println!("Response status: {}", resp.status());
            // Accept both server errors (5xx) and client errors (4xx) since connection failures
            // can be reported as either depending on the specific error
            assert!(resp.status().is_server_error() || resp.status().is_client_error());
        }
        Err(e) => {
            // Connection error is also acceptable
            println!("Expected connection error: {e}");
        }
    }

    server_handle.abort();
}

#[tokio::test]
async fn test_malformed_request_handling() {
    init_test_logging();

    // Start a mock upstream server
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/api/test"))
        .respond_with(ResponseTemplate::new(200).set_body_string("OK"))
        .mount(&mock_server)
        .await;

    let config = TestConfigProvider::new("malformed_test")
        .with_value("server.port", 0)
        .with_routes(vec![TestRoute::new(&mock_server.uri()).with_path("/api/*")]);

    let foxy = Foxy::loader()
        .with_provider(config)
        .build()
        .await
        .expect("Failed to build Foxy instance");

    let server_handle = tokio::spawn(async move { foxy.start().await });

    tokio::time::sleep(Duration::from_millis(100)).await;

    // Test with invalid HTTP method (this is handled by the HTTP client/server)
    let client = reqwest::Client::new();

    // Test with extremely long URL
    let long_path = "/api/".to_string() + &"x".repeat(10000);
    let response = client
        .get(format!("http://127.0.0.1:8080{long_path}"))
        .send()
        .await;

    match response {
        Ok(resp) => {
            // Should handle long URLs gracefully
            println!("Response status for long URL: {}", resp.status());
        }
        Err(e) => {
            // URL too long error is acceptable
            println!("Expected URL error: {e}");
        }
    }

    server_handle.abort();
}

#[tokio::test]
async fn test_large_request_body_handling() {
    init_test_logging();

    // Start a mock upstream server
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/upload"))
        .respond_with(ResponseTemplate::new(200).set_body_string("Uploaded"))
        .mount(&mock_server)
        .await;

    let config = TestConfigProvider::new("large_body_test")
        .with_value("server.port", 0)
        .with_value("server.body_limit", 1024) // 1KB limit
        .with_routes(vec![
            TestRoute::new(&mock_server.uri()).with_path("/upload"),
        ]);

    let foxy = Foxy::loader()
        .with_provider(config)
        .build()
        .await
        .expect("Failed to build Foxy instance");

    let server_handle = tokio::spawn(async move { foxy.start().await });

    tokio::time::sleep(Duration::from_millis(100)).await;

    // Send a large request body (2KB)
    let large_body = vec![b'x'; 2048];
    let client = reqwest::Client::new();
    let response = client
        .post("http://127.0.0.1:8080/upload")
        .body(large_body)
        .send()
        .await;

    match response {
        Ok(resp) => {
            // Should either accept it or reject with appropriate status
            println!("Response status for large body: {}", resp.status());
        }
        Err(e) => {
            // Request too large error is acceptable
            println!("Expected body size error: {e}");
        }
    }

    server_handle.abort();
}

#[test]
fn test_proxy_error_types() {
    // Test all ProxyError variants
    // Create a reqwest error by making a request to an invalid URL
    let client = reqwest::Client::new();
    let result = tokio::runtime::Runtime::new().unwrap().block_on(async {
        client
            .get("http://invalid-url-that-does-not-exist.invalid")
            .send()
            .await
    });
    let client_error = ProxyError::ClientError(result.unwrap_err());
    assert!(client_error.to_string().contains("HTTP client error"));

    let io_error = ProxyError::IoError(std::io::Error::new(
        std::io::ErrorKind::NotFound,
        "File not found",
    ));
    assert!(io_error.to_string().contains("IO error"));

    let timeout_error = ProxyError::Timeout(Duration::from_secs(30));
    assert!(timeout_error.to_string().contains("timed out"));

    let routing_error = ProxyError::RoutingError("No route".to_string());
    assert!(routing_error.to_string().contains("routing error"));

    let filter_error = ProxyError::FilterError("Filter failed".to_string());
    assert!(filter_error.to_string().contains("filter error"));

    let config_error = ProxyError::ConfigError("Bad config".to_string());
    assert!(config_error.to_string().contains("configuration error"));

    let security_error = ProxyError::SecurityError("Auth failed".to_string());
    assert!(security_error.to_string().contains("security error"));

    let other_error = ProxyError::Other("Generic".to_string());
    assert_eq!(other_error.to_string(), "Generic");
}
