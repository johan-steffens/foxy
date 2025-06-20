// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Mock upstream servers for testing Foxy API Gateway

use wiremock::{MockServer, Mock, ResponseTemplate, Request};
use wiremock::matchers::{method, path, header, query_param, query_param_is_missing, body_json};
use serde_json::{json, Value};
use std::time::Duration;

/// A builder for creating mock upstream servers with various behaviors
pub struct MockUpstreamBuilder {
    server: MockServer,
}

impl MockUpstreamBuilder {
    /// Create a new mock upstream server
    pub async fn new() -> Self {
        let server = MockServer::start().await;
        Self { server }
    }

    /// Get the URI of the mock server
    pub fn uri(&self) -> String {
        self.server.uri()
    }

    /// Add a simple GET endpoint that returns JSON
    pub async fn with_json_endpoint(
        &self,
        path_str: &str,
        status: u16,
        response_body: Value,
    ) -> &Self {
        Mock::given(method("GET"))
            .and(path(path_str))
            .respond_with(
                ResponseTemplate::new(status)
                    .set_body_json(response_body)
                    .insert_header("content-type", "application/json")
            )
            .mount(&self.server)
            .await;
        self
    }

    /// Add an endpoint that returns plain text
    pub async fn with_text_endpoint(
        &self,
        method_str: &str,
        path_str: &str,
        status: u16,
        response_body: &str,
    ) -> &Self {
        Mock::given(method(method_str))
            .and(path(path_str))
            .respond_with(
                ResponseTemplate::new(status)
                    .set_body_string(response_body)
                    .insert_header("content-type", "text/plain")
            )
            .mount(&self.server)
            .await;
        self
    }

    /// Add an endpoint that echoes request headers
    pub async fn with_header_echo_endpoint(&self, path_str: &str) -> &Self {
        Mock::given(method("GET"))
            .and(path(path_str))
            .respond_with(|req: &Request| {
                let headers: Value = req.headers.iter()
                    .map(|(name, value)| {
                        (name.to_string(), Value::String(value.to_str().unwrap_or("").to_string()))
                    })
                    .collect::<serde_json::Map<String, Value>>()
                    .into();

                ResponseTemplate::new(200)
                    .set_body_json(json!({ "headers": headers }))
                    .insert_header("content-type", "application/json")
            })
            .mount(&self.server)
            .await;
        self
    }

    /// Add an endpoint that echoes the request body
    pub async fn with_body_echo_endpoint(&self, path_str: &str) -> &Self {
        Mock::given(method("POST"))
            .and(path(path_str))
            .respond_with(|req: &Request| {
                let body = String::from_utf8_lossy(&req.body);
                ResponseTemplate::new(200)
                    .set_body_json(json!({ "received_body": body }))
                    .insert_header("content-type", "application/json")
            })
            .mount(&self.server)
            .await;
        self
    }

    /// Add an endpoint that requires specific headers
    pub async fn with_header_requirement(
        &self,
        path_str: &str,
        required_header: &str,
        required_value: &str,
        success_response: Value,
    ) -> &Self {
        // Success case with required header
        Mock::given(method("GET"))
            .and(path(path_str))
            .and(header(required_header, required_value))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(success_response)
                    .insert_header("content-type", "application/json")
            )
            .mount(&self.server)
            .await;

        // Failure case without required header
        Mock::given(method("GET"))
            .and(path(path_str))
            .respond_with(
                ResponseTemplate::new(401)
                    .set_body_json(json!({
                        "error": format!("Missing required header: {}", required_header)
                    }))
                    .insert_header("content-type", "application/json")
            )
            .mount(&self.server)
            .await;

        self
    }

    /// Add an endpoint that requires specific query parameters
    pub async fn with_query_requirement(
        &self,
        path_str: &str,
        required_param: &str,
        required_value: &str,
        success_response: Value,
    ) -> &Self {
        // Success case with required query param (register first, more specific)
        Mock::given(method("GET"))
            .and(path(path_str))
            .and(query_param(required_param, required_value))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(success_response)
                    .insert_header("content-type", "application/json")
            )
            .mount(&self.server)
            .await;

        // Failure case without required query param (register last, less specific)
        Mock::given(method("GET"))
            .and(path(path_str))
            .and(query_param_is_missing(required_param))
            .respond_with(
                ResponseTemplate::new(400)
                    .set_body_json(json!({
                        "error": format!("Missing required query parameter: {}", required_param)
                    }))
                    .insert_header("content-type", "application/json")
            )
            .mount(&self.server)
            .await;

        self
    }

    /// Add an endpoint with a delay to simulate slow responses
    pub async fn with_slow_endpoint(
        &self,
        path_str: &str,
        delay: Duration,
        response_body: Value,
    ) -> &Self {
        Mock::given(method("GET"))
            .and(path(path_str))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_delay(delay)
                    .set_body_json(response_body)
                    .insert_header("content-type", "application/json")
            )
            .mount(&self.server)
            .await;
        self
    }

    /// Add an endpoint that returns different responses based on request count
    pub async fn with_flaky_endpoint(&self, path_str: &str) -> &Self {
        // First call fails
        Mock::given(method("GET"))
            .and(path(path_str))
            .respond_with(ResponseTemplate::new(500).set_body_string("Internal Server Error"))
            .up_to_n_times(1)
            .mount(&self.server)
            .await;

        // Subsequent calls succeed
        Mock::given(method("GET"))
            .and(path(path_str))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(json!({ "status": "success", "attempt": "retry" }))
                    .insert_header("content-type", "application/json")
            )
            .mount(&self.server)
            .await;

        self
    }

    /// Add an endpoint that validates JSON request body
    pub async fn with_json_validation_endpoint(
        &self,
        path_str: &str,
        expected_json: Value,
        success_response: Value,
    ) -> &Self {
        // Success case with correct JSON
        Mock::given(method("POST"))
            .and(path(path_str))
            .and(body_json(&expected_json))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(success_response)
                    .insert_header("content-type", "application/json")
            )
            .mount(&self.server)
            .await;

        // Failure case with incorrect JSON
        Mock::given(method("POST"))
            .and(path(path_str))
            .respond_with(
                ResponseTemplate::new(400)
                    .set_body_json(json!({
                        "error": "Invalid JSON body"
                    }))
                    .insert_header("content-type", "application/json")
            )
            .mount(&self.server)
            .await;

        self
    }

    /// Add an endpoint that returns large responses
    pub async fn with_large_response_endpoint(&self, path_str: &str, size_kb: usize) -> &Self {
        let large_data = "x".repeat(size_kb * 1024);

        Mock::given(method("GET"))
            .and(path(path_str))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(json!({
                        "data": large_data,
                        "size_kb": size_kb
                    }))
                    .insert_header("content-type", "application/json")
            )
            .mount(&self.server)
            .await;
        self
    }

    /// Add an endpoint that simulates various HTTP status codes
    pub async fn with_status_code_endpoint(&self, path_str: &str, status: u16) -> &Self {
        let response_body = match status {
            200..=299 => json!({ "status": "success", "code": status }),
            400..=499 => json!({ "error": "client error", "code": status }),
            500..=599 => json!({ "error": "server error", "code": status }),
            _ => json!({ "status": "unknown", "code": status }),
        };

        Mock::given(method("GET"))
            .and(path(path_str))
            .respond_with(
                ResponseTemplate::new(status)
                    .set_body_json(response_body)
                    .insert_header("content-type", "application/json")
            )
            .mount(&self.server)
            .await;
        self
    }

    /// Add CORS-enabled endpoints
    pub async fn with_cors_endpoint(&self, path_str: &str, response_body: Value) -> &Self {
        // Handle preflight OPTIONS request
        Mock::given(method("OPTIONS"))
            .and(path(path_str))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("access-control-allow-origin", "*")
                    .insert_header("access-control-allow-methods", "GET, POST, PUT, DELETE, OPTIONS")
                    .insert_header("access-control-allow-headers", "content-type, authorization")
                    .insert_header("access-control-max-age", "86400")
            )
            .mount(&self.server)
            .await;

        // Handle actual request with CORS headers
        Mock::given(method("GET"))
            .and(path(path_str))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(response_body)
                    .insert_header("content-type", "application/json")
                    .insert_header("access-control-allow-origin", "*")
            )
            .mount(&self.server)
            .await;

        self
    }

    /// Get the underlying MockServer for advanced usage
    pub fn server(&self) -> &MockServer {
        &self.server
    }
}

/// Predefined mock server configurations for common testing scenarios
pub struct MockServerPresets;

impl MockServerPresets {
    /// Create a mock REST API server with CRUD endpoints
    pub async fn rest_api() -> MockUpstreamBuilder {
        let builder = MockUpstreamBuilder::new().await;
        
        // GET /users - list users
        builder.with_json_endpoint(
            "/users",
            200,
            json!([
                {"id": 1, "name": "Alice", "email": "alice@example.com"},
                {"id": 2, "name": "Bob", "email": "bob@example.com"}
            ])
        ).await;

        // GET /users/:id - get user by id
        builder.with_json_endpoint(
            "/users/1",
            200,
            json!({"id": 1, "name": "Alice", "email": "alice@example.com"})
        ).await;

        // POST /users - create user (echo body)
        builder.with_body_echo_endpoint("/users").await;

        builder
    }

    /// Create a mock server that simulates authentication
    pub async fn auth_server() -> MockUpstreamBuilder {
        let builder = MockUpstreamBuilder::new().await;
        
        // Protected endpoint requiring authorization header
        builder.with_header_requirement(
            "/protected",
            "authorization",
            "Bearer valid-token",
            json!({"message": "Access granted", "user": "authenticated"})
        ).await;

        // Login endpoint
        builder.with_json_validation_endpoint(
            "/login",
            json!({"username": "admin", "password": "secret"}),
            json!({"token": "valid-token", "expires_in": 3600})
        ).await;

        builder
    }

    /// Create a mock server with various error scenarios
    pub async fn error_server() -> MockUpstreamBuilder {
        let builder = MockUpstreamBuilder::new().await;
        
        // Various HTTP status codes
        for status in [400, 401, 403, 404, 429, 500, 502, 503] {
            let path = format!("/status/{}", status);
            builder.with_status_code_endpoint(&path, status).await;
        }

        // Slow endpoint
        builder.with_slow_endpoint(
            "/slow",
            Duration::from_secs(2),
            json!({"message": "This was slow"})
        ).await;

        // Flaky endpoint
        builder.with_flaky_endpoint("/flaky").await;

        builder
    }
}
