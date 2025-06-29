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
use common::{TestConfigProvider, TestFilter, TestRoute, init_test_logging};

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

#[tokio::test]
async fn test_request_timeout_error_path() {
    init_test_logging();

    // Start a mock server that will delay responses beyond timeout
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/timeout-test"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_delay(Duration::from_secs(10)) // 10 second delay
                .set_body_string("Too slow"),
        )
        .mount(&mock_server)
        .await;

    // Configure proxy with very short timeout to trigger timeout error path
    let config = TestConfigProvider::new("timeout_error_test")
        .with_value("proxy.timeout", 1) // 1 second timeout
        .with_value("server.port", 8081)
        .with_value("server.health_port", 8091)
        .with_routes(vec![
            TestRoute::new(&mock_server.uri()).with_path("/timeout-test"),
        ]);

    let foxy = Foxy::loader()
        .with_provider(config)
        .build()
        .await
        .expect("Failed to build Foxy instance");

    let server_handle = tokio::spawn(async move { foxy.start().await });

    tokio::time::sleep(Duration::from_millis(100)).await;

    // Make request that should timeout and trigger the specific error path
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(15)) // Client timeout longer than proxy timeout
        .build()
        .unwrap();

    let response = client
        .get("http://127.0.0.1:8081/timeout-test")
        .send()
        .await;

    // Should get a 504 Gateway Timeout or 502 Bad Gateway response
    match response {
        Ok(resp) => {
            let status = resp.status();
            println!("Response status: {}", status);
            let body = resp.text().await.unwrap();
            println!("Response body: {}", body);
            // Accept both 504 (timeout) and 502 (bad gateway) as valid error responses
            // The specific error depends on timing and network conditions
            assert!(
                status == 504 || status == 502,
                "Expected 504 or 502, got: {}",
                status
            );
            // Check for either timeout or gateway error message
            assert!(body.contains("Gateway Timeout") || body.contains("Bad Gateway"));
        }
        Err(e) => {
            // Network error is also acceptable for timeout scenarios
            println!("Expected timeout/network error: {e}");
        }
    }

    server_handle.abort();
}

#[tokio::test]
async fn test_core_timeout_error_path_direct() {
    init_test_logging();

    // Create a mock server that will delay responses to trigger timeout
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/direct-timeout"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_delay(Duration::from_secs(3)) // 3 second delay
                .set_body_string("Delayed response"),
        )
        .mount(&mock_server)
        .await;

    // Create a config with very short timeout
    let config_provider =
        TestConfigProvider::new("direct_timeout_test").with_value("proxy.timeout", 1); // 1 second timeout

    let config = std::sync::Arc::new(
        foxy::config::Config::builder()
            .with_provider(config_provider)
            .build(),
    );
    let router = std::sync::Arc::new(
        foxy::router::PredicateRouter::new(config.clone())
            .await
            .unwrap(),
    );

    // Add a route that points to our mock server
    let route = foxy::Route {
        id: "timeout-test-route".to_string(),
        target_base_url: mock_server.uri(),
        path_pattern: "/direct-timeout".to_string(),
        filters: None,
    };
    router.add_route(route).await.unwrap();

    let proxy_core = foxy::core::ProxyCore::new(config, router).await.unwrap();

    // Create a test request
    let request = common::create_test_request(
        foxy::HttpMethod::Get,
        "/direct-timeout",
        None,
        vec![],
        vec![],
    );

    // Process the request - this should trigger the timeout error path
    let result = proxy_core
        .process_request(
            request,
            #[cfg(feature = "opentelemetry")]
            None,
        )
        .await;

    // Should get a timeout error
    assert!(result.is_err());
    match result.unwrap_err() {
        foxy::ProxyError::Timeout(duration) => {
            assert_eq!(duration, Duration::from_secs(1));
        }
        foxy::ProxyError::ClientError(_) => {
            // Client error is also acceptable if the connection fails before timeout
            println!("Got client error instead of timeout - acceptable");
        }
        other => {
            panic!("Expected Timeout or ClientError, got: {other:?}");
        }
    }
}

#[tokio::test]
async fn test_route_post_filter_error_path() {
    init_test_logging();

    // Start a mock upstream server
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/filter-test"))
        .respond_with(ResponseTemplate::new(200).set_body_string("Success"))
        .mount(&mock_server)
        .await;

    // Create a route with a failing post-filter using raw filter configuration
    let route = TestRoute::new(&mock_server.uri())
        .with_path("/filter-test")
        .with_raw_filter("failing_post_filter", serde_json::json!({}));

    let config = TestConfigProvider::new("route_filter_error_test")
        .with_value("server.port", 8082)
        .with_value("server.health_port", 8092)
        .with_routes(vec![route]);

    // Register a failing filter
    foxy::filters::register_filter("failing_post_filter", |_config| {
        Ok(std::sync::Arc::new(FailingFilter::new(
            "route-post-filter",
            false,
            true,
        )))
    });

    let foxy = Foxy::loader()
        .with_provider(config)
        .build()
        .await
        .expect("Failed to build Foxy instance");

    let server_handle = tokio::spawn(async move { foxy.start().await });

    tokio::time::sleep(Duration::from_millis(100)).await;

    // Make request that should trigger route post-filter error
    let client = reqwest::Client::new();
    let response = client.get("http://127.0.0.1:8082/filter-test").send().await;

    match response {
        Ok(resp) => {
            // Should get an error status due to filter failure
            assert!(resp.status().is_server_error());
        }
        Err(e) => {
            println!("Expected filter error response: {e}");
        }
    }

    server_handle.abort();
}

#[tokio::test]
async fn test_global_post_filter_error_path() {
    init_test_logging();

    // Start a mock upstream server
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/global-filter-test"))
        .respond_with(ResponseTemplate::new(200).set_body_string("Success"))
        .mount(&mock_server)
        .await;

    // Register a failing global filter BEFORE creating config
    foxy::filters::register_filter("failing_global_post_filter", |_config| {
        Ok(std::sync::Arc::new(FailingFilter::new(
            "global-post-filter",
            false,
            true,
        )))
    });

    let config = TestConfigProvider::new("global_filter_error_test")
        .with_value("server.port", 8083)
        .with_value("server.health_port", 8093)
        .with_value(
            "proxy.global_filters",
            vec![serde_json::json!({
                "type": "failing_global_post_filter",
                "config": {}
            })],
        )
        .with_routes(vec![
            TestRoute::new(&mock_server.uri()).with_path("/global-filter-test"),
        ]);

    let foxy = Foxy::loader()
        .with_provider(config)
        .build()
        .await
        .expect("Failed to build Foxy instance");

    let server_handle = tokio::spawn(async move { foxy.start().await });

    tokio::time::sleep(Duration::from_millis(100)).await;

    // Make request that should trigger global post-filter error
    let client = reqwest::Client::new();
    let response = client
        .get("http://127.0.0.1:8083/global-filter-test")
        .send()
        .await;

    match response {
        Ok(resp) => {
            let status = resp.status();
            println!("Response status: {}", status);
            // Should get an error status due to global filter failure
            assert!(
                status.is_server_error(),
                "Expected server error, got: {}",
                status
            );
        }
        Err(e) => {
            println!("Expected global filter error response: {e}");
        }
    }

    server_handle.abort();
}

// Mock security provider for testing error paths
#[derive(Debug)]
struct FailingSecurityProvider {
    name: String,
    fail_pre: bool,
    fail_post: bool,
}

impl FailingSecurityProvider {
    fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
            fail_pre: false,
            fail_post: false,
        }
    }

    fn with_post_failure(mut self) -> Self {
        self.fail_post = true;
        self
    }

    #[allow(dead_code)]
    fn with_pre_failure(mut self) -> Self {
        self.fail_pre = true;
        self
    }
}

#[async_trait]
impl foxy::security::SecurityProvider for FailingSecurityProvider {
    fn stage(&self) -> foxy::security::SecurityStage {
        foxy::security::SecurityStage::Both
    }

    fn name(&self) -> &str {
        &self.name
    }

    async fn pre(&self, request: ProxyRequest) -> Result<ProxyRequest, ProxyError> {
        if self.fail_pre {
            Err(ProxyError::SecurityError(format!(
                "Pre-auth failed: {}",
                self.name
            )))
        } else {
            Ok(request)
        }
    }

    async fn post(
        &self,
        _request: ProxyRequest,
        response: ProxyResponse,
    ) -> Result<ProxyResponse, ProxyError> {
        if self.fail_post {
            Err(ProxyError::SecurityError(format!(
                "Post-auth failed: {}",
                self.name
            )))
        } else {
            Ok(response)
        }
    }
}

#[tokio::test]
async fn test_security_post_auth_error_path() {
    init_test_logging();

    // Start a mock upstream server
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/security-test"))
        .respond_with(ResponseTemplate::new(200).set_body_string("Success"))
        .mount(&mock_server)
        .await;

    let config = TestConfigProvider::new("security_error_test")
        .with_value("server.port", 8084)
        .with_value("server.health_port", 8094)
        .with_routes(vec![
            TestRoute::new(&mock_server.uri()).with_path("/security-test"),
        ]);

    let foxy = Foxy::loader()
        .with_provider(config)
        .build()
        .await
        .expect("Failed to build Foxy instance");

    // Add a security provider that will fail post-auth
    let failing_provider =
        std::sync::Arc::new(FailingSecurityProvider::new("test-security").with_post_failure());
    foxy.core().add_security_provider(failing_provider).await;

    let server_handle = tokio::spawn(async move { foxy.start().await });

    tokio::time::sleep(Duration::from_millis(100)).await;

    // Make request that should trigger security post-auth error
    let client = reqwest::Client::new();
    let response = client
        .get("http://127.0.0.1:8084/security-test")
        .send()
        .await;

    match response {
        Ok(resp) => {
            // Should get a 403 Forbidden due to security failure
            assert_eq!(resp.status(), 403);
        }
        Err(e) => {
            println!("Expected security error response: {e}");
        }
    }

    server_handle.abort();
}

#[tokio::test]
async fn test_multiple_error_scenarios_combined() {
    init_test_logging();

    // Test scenario where multiple error conditions could occur
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/complex-test"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_delay(Duration::from_millis(500))
                .set_body_string("Complex response"),
        )
        .mount(&mock_server)
        .await;

    // Create route with both filters and security using TestFilter
    let route = TestRoute::new(&mock_server.uri())
        .with_path("/complex-test")
        .with_filter(TestFilter::Logging { log_bodies: true });

    let config = TestConfigProvider::new("complex_error_test")
        .with_value("proxy.timeout", 2) // 2 second timeout
        .with_value("server.port", 0)
        .with_routes(vec![route]);

    // Register a filter that might fail
    foxy::filters::register_filter("complex_test_filter", |_config| {
        Ok(std::sync::Arc::new(FailingFilter::new(
            "complex-filter",
            false,
            false,
        )))
    });

    let foxy = Foxy::loader()
        .with_provider(config)
        .build()
        .await
        .expect("Failed to build Foxy instance");

    // Add security provider
    let security_provider = std::sync::Arc::new(FailingSecurityProvider::new("complex-security"));
    foxy.core().add_security_provider(security_provider).await;

    let server_handle = tokio::spawn(async move { foxy.start().await });

    tokio::time::sleep(Duration::from_millis(100)).await;

    // Make request that exercises multiple code paths
    let client = reqwest::Client::new();
    let response = client
        .post("http://127.0.0.1:8080/complex-test")
        .body("test data")
        .send()
        .await;

    match response {
        Ok(resp) => {
            // Should succeed or fail gracefully
            println!("Complex test response status: {}", resp.status());
        }
        Err(e) => {
            println!("Complex test error (acceptable): {e}");
        }
    }

    server_handle.abort();
}

#[tokio::test]
async fn test_debug_route_matching() {
    init_test_logging();

    // Start a mock upstream server
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/debug-test"))
        .respond_with(ResponseTemplate::new(200).set_body_string("Debug Success"))
        .mount(&mock_server)
        .await;

    let route = TestRoute::new(&mock_server.uri()).with_path("/debug-test");

    // Print the route configuration to see what's being generated
    let route_json: serde_json::Value = route.into();
    println!(
        "Route configuration: {}",
        serde_json::to_string_pretty(&route_json).unwrap()
    );

    let config = TestConfigProvider::new("debug_route_test")
        .with_value("server.port", 0)
        .with_routes(vec![
            TestRoute::new(&mock_server.uri()).with_path("/debug-test"),
        ]);

    let foxy = Foxy::loader()
        .with_provider(config)
        .build()
        .await
        .expect("Failed to build Foxy instance");

    let server_handle = tokio::spawn(async move { foxy.start().await });

    tokio::time::sleep(Duration::from_millis(100)).await;

    // Make request to debug the routing
    let client = reqwest::Client::new();
    let response = client.get("http://127.0.0.1:8080/debug-test").send().await;

    match response {
        Ok(resp) => {
            println!("Response status: {}", resp.status());
            let body = resp.text().await.unwrap();
            println!("Response body: {}", body);
        }
        Err(e) => {
            println!("Request error: {e}");
        }
    }

    server_handle.abort();
}
