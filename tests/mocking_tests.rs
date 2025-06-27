// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Tests for the mocking infrastructure

use foxy::Foxy;
use serde_json::json;
use serial_test::serial;
use std::time::Duration;

mod common;
mod mocks;

use common::{TestConfigProvider, TestRoute, init_test_logging};
use mocks::upstream_servers::{MockServerPresets, MockUpstreamBuilder};

#[tokio::test]
#[serial]
async fn test_mock_upstream_json_endpoint() {
    init_test_logging();

    let mock_upstream = MockUpstreamBuilder::new().await;
    mock_upstream
        .with_json_endpoint(
            "/api/data",
            200,
            json!({"message": "Hello from mock", "data": [1, 2, 3]}),
        )
        .await;

    let config = TestConfigProvider::new("mock_test")
        .with_value("server.port", 0)
        .with_routes(vec![
            TestRoute::new(&mock_upstream.uri()).with_path("/api/*"),
        ]);

    let foxy = Foxy::loader()
        .with_provider(config)
        .build()
        .await
        .expect("Failed to build Foxy instance");

    let server_handle = tokio::spawn(async move { foxy.start().await });

    tokio::time::sleep(Duration::from_millis(100)).await;

    let client = reqwest::Client::new();
    let response = client
        .get("http://127.0.0.1:8080/api/data")
        .send()
        .await
        .expect("Request failed");

    assert_eq!(response.status(), 200);

    let body: serde_json::Value = response.json().await.expect("Failed to parse JSON");
    assert_eq!(body["message"], "Hello from mock");
    assert_eq!(body["data"].as_array().unwrap().len(), 3);

    server_handle.abort();
}

#[tokio::test]
#[serial]
async fn test_mock_upstream_header_echo() {
    init_test_logging();

    let mock_upstream = MockUpstreamBuilder::new().await;
    mock_upstream.with_header_echo_endpoint("/echo").await;

    let config = TestConfigProvider::new("header_echo_test")
        .with_value("server.port", 0)
        .with_routes(vec![
            TestRoute::new(&mock_upstream.uri()).with_path("/echo"),
        ]);

    let foxy = Foxy::loader()
        .with_provider(config)
        .build()
        .await
        .expect("Failed to build Foxy instance");

    let server_handle = tokio::spawn(async move { foxy.start().await });

    tokio::time::sleep(Duration::from_millis(100)).await;

    let client = reqwest::Client::new();
    let response = client
        .get("http://127.0.0.1:8080/echo")
        .header("x-test-header", "test-value")
        .header("user-agent", "test-client")
        .send()
        .await
        .expect("Request failed");

    assert_eq!(response.status(), 200);

    let body: serde_json::Value = response.json().await.expect("Failed to parse JSON");
    let headers = body["headers"].as_object().unwrap();

    assert!(headers.contains_key("x-test-header"));
    assert!(headers.contains_key("user-agent"));

    server_handle.abort();
}

#[tokio::test]
#[serial]
async fn test_mock_upstream_header_requirement() {
    init_test_logging();

    let mock_upstream = MockUpstreamBuilder::new().await;
    mock_upstream
        .with_header_requirement(
            "/protected",
            "authorization",
            "Bearer secret-token",
            json!({"access": "granted"}),
        )
        .await;

    let config = TestConfigProvider::new("auth_test")
        .with_value("server.port", 0)
        .with_routes(vec![
            TestRoute::new(&mock_upstream.uri()).with_path("/protected"),
        ]);

    let foxy = Foxy::loader()
        .with_provider(config)
        .build()
        .await
        .expect("Failed to build Foxy instance");

    let server_handle = tokio::spawn(async move { foxy.start().await });

    tokio::time::sleep(Duration::from_millis(100)).await;

    let client = reqwest::Client::new();

    // Test without required header - should fail
    let response = client
        .get("http://127.0.0.1:8080/protected")
        .send()
        .await
        .expect("Request failed");

    assert_eq!(response.status(), 401);

    // Test with required header - should succeed
    let response = client
        .get("http://127.0.0.1:8080/protected")
        .header("authorization", "Bearer secret-token")
        .send()
        .await
        .expect("Request failed");

    assert_eq!(response.status(), 200);

    let body: serde_json::Value = response.json().await.expect("Failed to parse JSON");
    assert_eq!(body["access"], "granted");

    server_handle.abort();
}

#[tokio::test]
#[serial]
async fn test_mock_upstream_slow_endpoint() {
    init_test_logging();

    let mock_upstream = MockUpstreamBuilder::new().await;
    mock_upstream
        .with_slow_endpoint(
            "/slow",
            Duration::from_millis(500),
            json!({"message": "This was slow"}),
        )
        .await;

    let config = TestConfigProvider::new("slow_test")
        .with_value("server.port", 0)
        .with_routes(vec![
            TestRoute::new(&mock_upstream.uri()).with_path("/slow"),
        ]);

    let foxy = Foxy::loader()
        .with_provider(config)
        .build()
        .await
        .expect("Failed to build Foxy instance");

    let server_handle = tokio::spawn(async move { foxy.start().await });

    tokio::time::sleep(Duration::from_millis(100)).await;

    let start = std::time::Instant::now();

    let client = reqwest::Client::new();
    let response = client
        .get("http://127.0.0.1:8080/slow")
        .send()
        .await
        .expect("Request failed");

    let elapsed = start.elapsed();

    assert_eq!(response.status(), 200);
    assert!(elapsed >= Duration::from_millis(400)); // Account for some variance

    let body: serde_json::Value = response.json().await.expect("Failed to parse JSON");
    assert_eq!(body["message"], "This was slow");

    server_handle.abort();
}

#[tokio::test]
#[serial]
async fn test_mock_upstream_flaky_endpoint() {
    init_test_logging();

    let mock_upstream = MockUpstreamBuilder::new().await;
    mock_upstream.with_flaky_endpoint("/flaky").await;

    let config = TestConfigProvider::new("flaky_test")
        .with_value("server.port", 0)
        .with_routes(vec![
            TestRoute::new(&mock_upstream.uri()).with_path("/flaky"),
        ]);

    let foxy = Foxy::loader()
        .with_provider(config)
        .build()
        .await
        .expect("Failed to build Foxy instance");

    let server_handle = tokio::spawn(async move { foxy.start().await });

    tokio::time::sleep(Duration::from_millis(100)).await;

    let client = reqwest::Client::new();

    // First request should fail
    let response1 = client
        .get("http://127.0.0.1:8080/flaky")
        .send()
        .await
        .expect("Request failed");

    assert_eq!(response1.status(), 500);

    // Second request should succeed
    let response2 = client
        .get("http://127.0.0.1:8080/flaky")
        .send()
        .await
        .expect("Request failed");

    assert_eq!(response2.status(), 200);

    let body: serde_json::Value = response2.json().await.expect("Failed to parse JSON");
    assert_eq!(body["status"], "success");

    server_handle.abort();
}

#[tokio::test]
#[serial]
async fn test_mock_server_presets_rest_api() {
    init_test_logging();

    let mock_upstream = MockServerPresets::rest_api().await;

    let config = TestConfigProvider::new("rest_api_test")
        .with_value("server.port", 0)
        .with_routes(vec![TestRoute::new(&mock_upstream.uri()).with_path("/*")]);

    let foxy = Foxy::loader()
        .with_provider(config)
        .build()
        .await
        .expect("Failed to build Foxy instance");

    let server_handle = tokio::spawn(async move { foxy.start().await });

    tokio::time::sleep(Duration::from_millis(100)).await;

    let client = reqwest::Client::new();

    // Test GET /users
    let response = client
        .get("http://127.0.0.1:8080/users")
        .send()
        .await
        .expect("Request failed");

    assert_eq!(response.status(), 200);

    let users: serde_json::Value = response.json().await.expect("Failed to parse JSON");
    assert!(users.is_array());
    assert_eq!(users.as_array().unwrap().len(), 2);

    // Test GET /users/1
    let response = client
        .get("http://127.0.0.1:8080/users/1")
        .send()
        .await
        .expect("Request failed");

    assert_eq!(response.status(), 200);

    let user: serde_json::Value = response.json().await.expect("Failed to parse JSON");
    assert_eq!(user["id"], 1);
    assert_eq!(user["name"], "Alice");

    server_handle.abort();
}

#[tokio::test]
#[serial]
async fn test_mock_server_presets_auth_server() {
    init_test_logging();

    let mock_upstream = MockServerPresets::auth_server().await;

    let config = TestConfigProvider::new("auth_server_test")
        .with_value("server.port", 0)
        .with_routes(vec![TestRoute::new(&mock_upstream.uri()).with_path("/*")]);

    let foxy = Foxy::loader()
        .with_provider(config)
        .build()
        .await
        .expect("Failed to build Foxy instance");

    let server_handle = tokio::spawn(async move { foxy.start().await });

    tokio::time::sleep(Duration::from_millis(100)).await;

    let client = reqwest::Client::new();

    // Test login
    let login_response = client
        .post("http://127.0.0.1:8080/login")
        .json(&json!({"username": "admin", "password": "secret"}))
        .send()
        .await
        .expect("Login request failed");

    assert_eq!(login_response.status(), 200);

    let login_body: serde_json::Value = login_response.json().await.expect("Failed to parse JSON");
    assert_eq!(login_body["token"], "valid-token");

    // Test protected endpoint with token
    let protected_response = client
        .get("http://127.0.0.1:8080/protected")
        .header("authorization", "Bearer valid-token")
        .send()
        .await
        .expect("Protected request failed");

    assert_eq!(protected_response.status(), 200);

    let protected_body: serde_json::Value = protected_response
        .json()
        .await
        .expect("Failed to parse JSON");
    assert_eq!(protected_body["message"], "Access granted");

    server_handle.abort();
}

#[tokio::test]
#[serial]
async fn test_mock_server_presets_error_server() {
    init_test_logging();

    let mock_upstream = MockServerPresets::error_server().await;

    let config = TestConfigProvider::new("error_server_test")
        .with_value("server.port", 0)
        .with_routes(vec![TestRoute::new(&mock_upstream.uri()).with_path("/*")]);

    let foxy = Foxy::loader()
        .with_provider(config)
        .build()
        .await
        .expect("Failed to build Foxy instance");

    let server_handle = tokio::spawn(async move { foxy.start().await });

    tokio::time::sleep(Duration::from_millis(100)).await;

    let client = reqwest::Client::new();

    // Test various HTTP status codes
    let status_codes = [400, 401, 403, 404, 429, 500, 502, 503];

    for status in status_codes {
        let response = client
            .get(format!("http://127.0.0.1:8080/status/{}", status))
            .send()
            .await
            .expect("Request failed");

        assert_eq!(response.status(), status);
        let body: serde_json::Value = response.json().await.expect("Failed to parse JSON");

        if (400..500).contains(&status) {
            assert_eq!(body["error"], "client error");
        } else if status >= 500 {
            assert_eq!(body["error"], "server error");
        }
        assert_eq!(body["code"], status);
    }

    // Test slow endpoint (2 second delay)
    let start_time = std::time::Instant::now();
    let slow_response = client
        .get("http://127.0.0.1:8080/slow")
        .send()
        .await
        .expect("Slow request failed");
    let elapsed = start_time.elapsed();

    assert_eq!(slow_response.status(), 200);
    assert!(
        elapsed.as_secs() >= 2,
        "Slow endpoint should take at least 2 seconds"
    );

    let slow_body: serde_json::Value = slow_response.json().await.expect("Failed to parse JSON");
    assert_eq!(slow_body["message"], "This was slow");

    // Test flaky endpoint (should fail first, then succeed)
    let flaky_response1 = client
        .get("http://127.0.0.1:8080/flaky")
        .send()
        .await
        .expect("Flaky request 1 failed");
    assert_eq!(flaky_response1.status(), 500);

    let flaky_response2 = client
        .get("http://127.0.0.1:8080/flaky")
        .send()
        .await
        .expect("Flaky request 2 failed");
    assert_eq!(flaky_response2.status(), 200);

    let flaky_body: serde_json::Value = flaky_response2.json().await.expect("Failed to parse JSON");
    assert_eq!(flaky_body["status"], "success");
    assert_eq!(flaky_body["attempt"], "retry");

    server_handle.abort();
}

#[tokio::test]
#[serial]
async fn test_mock_upstream_text_endpoint() {
    init_test_logging();

    let mock_upstream = MockUpstreamBuilder::new().await;
    mock_upstream
        .with_text_endpoint("GET", "/text", 200, "Hello, World!")
        .await;

    let config = TestConfigProvider::new("text_endpoint_test")
        .with_value("server.port", 0)
        .with_routes(vec![TestRoute::new(&mock_upstream.uri()).with_path("/*")]);

    let foxy = Foxy::loader()
        .with_provider(config)
        .build()
        .await
        .expect("Failed to build Foxy instance");

    let server_handle = tokio::spawn(async move { foxy.start().await });

    tokio::time::sleep(Duration::from_millis(100)).await;

    let client = reqwest::Client::new();

    let response = client
        .get("http://127.0.0.1:8080/text")
        .send()
        .await
        .expect("Request failed");

    assert_eq!(response.status(), 200);
    assert_eq!(
        response.headers().get("content-type").unwrap(),
        "text/plain"
    );

    let text = response.text().await.expect("Failed to get text");
    assert_eq!(text, "Hello, World!");

    server_handle.abort();
}

#[tokio::test]
#[serial]
async fn test_mock_upstream_query_requirement() {
    init_test_logging();

    let mock_upstream = MockUpstreamBuilder::new().await;
    mock_upstream
        .with_query_requirement(
            "/search",
            "q",
            "test",
            json!({"results": ["item1", "item2"]}),
        )
        .await;

    let config = TestConfigProvider::new("query_requirement_test")
        .with_value("server.port", 0)
        .with_routes(vec![TestRoute::new(&mock_upstream.uri()).with_path("/*")]);

    let foxy = Foxy::loader()
        .with_provider(config)
        .build()
        .await
        .expect("Failed to build Foxy instance");

    let server_handle = tokio::spawn(async move { foxy.start().await });

    tokio::time::sleep(Duration::from_millis(100)).await;

    let client = reqwest::Client::new();

    // Test without required query parameter first (should fail)
    let response = client
        .get("http://127.0.0.1:8080/search")
        .send()
        .await
        .expect("Request failed");

    assert_eq!(response.status(), 400);
    let body: serde_json::Value = response.json().await.expect("Failed to parse JSON");
    assert_eq!(body["error"], "Missing required query parameter: q");

    // Test with correct query parameter (should succeed)
    let response = client
        .get("http://127.0.0.1:8080/search?q=test")
        .send()
        .await
        .expect("Request failed");

    assert_eq!(response.status(), 200);
    let body: serde_json::Value = response.json().await.expect("Failed to parse JSON");
    assert_eq!(body["results"].as_array().unwrap().len(), 2);

    server_handle.abort();
}

#[tokio::test]
#[serial]
async fn test_mock_upstream_large_response() {
    init_test_logging();

    let mock_upstream = MockUpstreamBuilder::new().await;
    mock_upstream
        .with_large_response_endpoint("/large", 10)
        .await; // 10KB response

    let config = TestConfigProvider::new("large_response_test")
        .with_value("server.port", 0)
        .with_routes(vec![TestRoute::new(&mock_upstream.uri()).with_path("/*")]);

    let foxy = Foxy::loader()
        .with_provider(config)
        .build()
        .await
        .expect("Failed to build Foxy instance");

    let server_handle = tokio::spawn(async move { foxy.start().await });

    tokio::time::sleep(Duration::from_millis(100)).await;

    let client = reqwest::Client::new();

    let response = client
        .get("http://127.0.0.1:8080/large")
        .send()
        .await
        .expect("Request failed");

    assert_eq!(response.status(), 200);

    let body: serde_json::Value = response.json().await.expect("Failed to parse JSON");
    assert_eq!(body["size_kb"], 10);

    // Verify the data field contains the expected amount of data
    let data_str = body["data"].as_str().expect("Data should be a string");
    assert_eq!(data_str.len(), 10 * 1024); // 10KB
    assert!(data_str.chars().all(|c| c == 'x')); // All 'x' characters

    server_handle.abort();
}

#[tokio::test]
#[serial]
async fn test_mock_upstream_cors_endpoint() {
    init_test_logging();

    let mock_upstream = MockUpstreamBuilder::new().await;
    mock_upstream
        .with_cors_endpoint("/api/data", json!({"message": "CORS enabled"}))
        .await;

    let config = TestConfigProvider::new("cors_test")
        .with_value("server.port", 0)
        .with_routes(vec![TestRoute::new(&mock_upstream.uri()).with_path("/*")]);

    let foxy = Foxy::loader()
        .with_provider(config)
        .build()
        .await
        .expect("Failed to build Foxy instance");

    let server_handle = tokio::spawn(async move { foxy.start().await });

    tokio::time::sleep(Duration::from_millis(100)).await;

    let client = reqwest::Client::new();

    // Test OPTIONS preflight request
    let options_response = client
        .request(reqwest::Method::OPTIONS, "http://127.0.0.1:8080/api/data")
        .send()
        .await
        .expect("OPTIONS request failed");

    assert_eq!(options_response.status(), 200);
    assert_eq!(
        options_response
            .headers()
            .get("access-control-allow-origin")
            .unwrap(),
        "*"
    );
    assert_eq!(
        options_response
            .headers()
            .get("access-control-allow-methods")
            .unwrap(),
        "GET, POST, PUT, DELETE, OPTIONS"
    );

    // Test actual GET request with CORS headers
    let get_response = client
        .get("http://127.0.0.1:8080/api/data")
        .send()
        .await
        .expect("GET request failed");

    assert_eq!(get_response.status(), 200);
    assert_eq!(
        get_response
            .headers()
            .get("access-control-allow-origin")
            .unwrap(),
        "*"
    );

    let body: serde_json::Value = get_response.json().await.expect("Failed to parse JSON");
    assert_eq!(body["message"], "CORS enabled");

    server_handle.abort();
}
