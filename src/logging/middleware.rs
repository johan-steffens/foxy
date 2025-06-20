// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! HTTP middleware for request/response logging with trace context.

use hyper::{Request, Response};
use std::task::{Context, Poll};
use std::pin::Pin;
use std::future::Future;
use futures_util::ready;
use std::time::Duration;
use crate::logging::structured::{RequestInfo, generate_trace_id};
use crate::logging::config::LoggingConfig;
use slog_scope;
use std::sync::Arc;
use std::net::SocketAddr;

/// Middleware for request/response logging with trace context
#[derive(Debug, Clone)]
pub struct LoggingMiddleware {
    config: Arc<LoggingConfig>,
}

impl LoggingMiddleware {
    /// Create a new logging middleware
    pub fn new(config: LoggingConfig) -> Self {
        Self {
            config: Arc::new(config),
        }
    }
    
    /// Process a request and add trace context
    pub async fn process<B>(
        &self,
        req: Request<B>,
        remote_addr: Option<SocketAddr>,
    ) -> (Request<B>, RequestInfo) {
        let method = req.method().to_string();
        let path = req.uri().path().to_string();
        let remote_addr_str = remote_addr
            .map(|addr| addr.to_string())
            .unwrap_or_else(|| "unknown".to_string());
        
        let user_agent = req
            .headers()
            .get(hyper::header::USER_AGENT)
            .and_then(|h| h.to_str().ok())
            .unwrap_or("unknown")
            .to_string();
        
        // Check for existing trace ID in headers if propagation is enabled
        let trace_id = if self.config.propagate_trace_id {
            req.headers()
                .get(&self.config.trace_id_header)
                .and_then(|h| h.to_str().ok())
                .filter(|s| !s.is_empty()) // Filter out empty strings
                .map(|s| s.to_string())
                .unwrap_or_else(generate_trace_id)
        } else {
            generate_trace_id()
        };
        
        let request_info = RequestInfo {
            trace_id,
            method,
            path,
            remote_addr: remote_addr_str,
            user_agent,
            start_time_ms: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis(),
        };
        
        // Log the incoming request with trace context
        if self.config.structured {
            let logger = slog_scope::logger();
            slog::info!(logger, "Request received";
                "trace_id" => &request_info.trace_id,
                "method" => &request_info.method,
                "path" => &request_info.path,
                "remote_addr" => &request_info.remote_addr,
                "user_agent" => &request_info.user_agent
            );
        } else {
            log::info!(
                "Request received: {} {} from {} (trace_id: {})",
                request_info.method,
                request_info.path,
                request_info.remote_addr,
                request_info.trace_id
            );
        }
        
        (req, request_info)
    }
    
    /// Log the response with timing information
    pub fn log_response<B>(
        &self,
        response: &Response<B>,
        request_info: &RequestInfo,
        upstream_duration: Option<Duration>,
    ) {
        let status = response.status().as_u16();
        let elapsed_ms = request_info.elapsed_ms();
        let upstream_ms = upstream_duration
            .map(|d| d.as_millis())
            .unwrap_or(0);
        let internal_ms = elapsed_ms.saturating_sub(upstream_ms);
        
        if self.config.structured {
            let logger = slog_scope::logger();
            slog::info!(logger, "Response completed";
                "trace_id" => &request_info.trace_id,
                "method" => &request_info.method,
                "path" => &request_info.path,
                "status" => status,
                "elapsed_ms" => elapsed_ms,
                "upstream_ms" => upstream_ms,
                "internal_ms" => internal_ms
            );
        } else {
            log::info!(
                "[timing] {} {} -> {} | total={}ms upstream={}ms internal={}ms (trace_id: {})",
                request_info.method,
                request_info.path,
                status,
                elapsed_ms,
                upstream_ms,
                internal_ms,
                request_info.trace_id
            );
        }
    }
}

/// Future that wraps a response future and adds trace ID header
pub struct TracedResponseFuture<F> {
    inner: F,
    trace_id: String,
    trace_header: String,
    include_trace_id: bool,
}

impl<F, B, E> Future for TracedResponseFuture<F>
where
    F: Future<Output = Result<Response<B>, E>> + Unpin,
{
    type Output = Result<Response<B>, E>;
    
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let result = ready!(Pin::new(&mut self.inner).poll(cx));
        
        Poll::Ready(match result {
            Ok(mut response) => {
                // Add trace ID header to response if enabled
                if self.include_trace_id {
                    let header_name = hyper::header::HeaderName::from_bytes(self.trace_header.as_bytes())
                        .unwrap_or_else(|_| hyper::header::HeaderName::from_static("x-trace-id"));
                    
                    response.headers_mut().insert(
                        header_name,
                        hyper::header::HeaderValue::from_str(&self.trace_id)
                            .unwrap_or_else(|_| hyper::header::HeaderValue::from_static("invalid-trace-id")),
                    );
                }
                Ok(response)
            }
            Err(e) => Err(e),
        })
    }
}

/// Extension trait for response futures to add trace context
pub trait ResponseFutureExt: Sized {
    /// Add trace ID header to the response
    fn with_trace_id(
        self,
        trace_id: String,
        trace_header: String,
        include_trace_id: bool,
    ) -> TracedResponseFuture<Self>;
}

impl<F, B, E> ResponseFutureExt for F
where
    F: Future<Output = Result<Response<B>, E>> + Unpin,
{
    fn with_trace_id(
        self,
        trace_id: String,
        trace_header: String,
        include_trace_id: bool,
    ) -> TracedResponseFuture<Self> {
        TracedResponseFuture {
            inner: self,
            trace_id,
            trace_header,
            include_trace_id,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::logging::config::LoggingConfig;
    use hyper::{Request, Response, Method};
    use http_body_util::Empty;
    use bytes::Bytes;
    use std::net::{SocketAddr, IpAddr, Ipv4Addr};
    use std::time::Duration;
    use std::future::Future;
    use std::pin::Pin;
    use std::task::{Context, Poll};

    fn create_test_config() -> LoggingConfig {
        LoggingConfig {
            structured: false,
            format: "terminal".to_string(),
            level: "info".to_string(),
            include_location: true,
            include_thread_id: true,
            include_trace_id: true,
            propagate_trace_id: false,
            trace_id_header: "x-trace-id".to_string(),
            static_fields: std::collections::HashMap::new(),
        }
    }

    fn create_test_config_structured() -> LoggingConfig {
        LoggingConfig {
            structured: true,
            format: "json".to_string(),
            level: "info".to_string(),
            include_location: true,
            include_thread_id: true,
            include_trace_id: true,
            propagate_trace_id: false,
            trace_id_header: "x-trace-id".to_string(),
            static_fields: std::collections::HashMap::new(),
        }
    }

    fn create_test_config_with_propagation() -> LoggingConfig {
        LoggingConfig {
            structured: false,
            format: "terminal".to_string(),
            level: "info".to_string(),
            include_location: true,
            include_thread_id: true,
            include_trace_id: true,
            propagate_trace_id: true,
            trace_id_header: "x-trace-id".to_string(),
            static_fields: std::collections::HashMap::new(),
        }
    }

    fn create_test_request() -> Request<Empty<Bytes>> {
        Request::builder()
            .method(Method::GET)
            .uri("/test/path")
            .header("user-agent", "test-agent/1.0")
            .body(Empty::<Bytes>::new())
            .unwrap()
    }

    fn create_test_request_with_trace_id(trace_id: &str) -> Request<Empty<Bytes>> {
        Request::builder()
            .method(Method::GET)
            .uri("/test/path")
            .header("user-agent", "test-agent/1.0")
            .header("x-trace-id", trace_id)
            .body(Empty::<Bytes>::new())
            .unwrap()
    }

    fn create_test_socket_addr() -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)), 8080)
    }

    #[tokio::test]
    async fn test_logging_middleware_new() {
        let config = create_test_config();
        let middleware = LoggingMiddleware::new(config);

        // Test that the middleware is created successfully
        assert!(!middleware.config.structured);
        assert!(!middleware.config.propagate_trace_id);
    }

    #[tokio::test]
    async fn test_process_request_basic() {
        let config = create_test_config();
        let middleware = LoggingMiddleware::new(config);
        let request = create_test_request();
        let remote_addr = Some(create_test_socket_addr());

        let (processed_req, request_info) = middleware.process(request, remote_addr).await;

        // Verify request is returned unchanged
        assert_eq!(processed_req.method(), Method::GET);
        assert_eq!(processed_req.uri().path(), "/test/path");

        // Verify request info is populated
        assert_eq!(request_info.method, "GET");
        assert_eq!(request_info.path, "/test/path");
        assert_eq!(request_info.remote_addr, "192.168.1.100:8080");
        assert_eq!(request_info.user_agent, "test-agent/1.0");
        assert!(!request_info.trace_id.is_empty());
    }

    #[tokio::test]
    async fn test_process_request_no_remote_addr() {
        let config = create_test_config();
        let middleware = LoggingMiddleware::new(config);
        let request = create_test_request();

        let (_, request_info) = middleware.process(request, None).await;

        assert_eq!(request_info.remote_addr, "unknown");
    }

    #[tokio::test]
    async fn test_process_request_no_user_agent() {
        let config = create_test_config();
        let middleware = LoggingMiddleware::new(config);
        let request = Request::builder()
            .method(Method::POST)
            .uri("/api/test")
            .body(Empty::<Bytes>::new())
            .unwrap();

        let (_, request_info) = middleware.process(request, None).await;

        assert_eq!(request_info.method, "POST");
        assert_eq!(request_info.path, "/api/test");
        assert_eq!(request_info.user_agent, "unknown");
    }

    #[tokio::test]
    async fn test_process_request_with_trace_propagation() {
        let config = create_test_config_with_propagation();
        let middleware = LoggingMiddleware::new(config);
        let existing_trace_id = "existing-trace-123";
        let request = create_test_request_with_trace_id(existing_trace_id);

        let (_, request_info) = middleware.process(request, None).await;

        assert_eq!(request_info.trace_id, existing_trace_id);
    }

    #[tokio::test]
    async fn test_process_request_without_trace_propagation() {
        let config = create_test_config();
        let middleware = LoggingMiddleware::new(config);
        let request = create_test_request_with_trace_id("existing-trace-123");

        let (_, request_info) = middleware.process(request, None).await;

        // Should generate new trace ID, not use existing one
        assert_ne!(request_info.trace_id, "existing-trace-123");
        assert!(!request_info.trace_id.is_empty());
    }

    #[tokio::test]
    async fn test_process_request_invalid_trace_header() {
        let config = create_test_config_with_propagation();
        let middleware = LoggingMiddleware::new(config);

        // Create a request with an invalid trace header value that can't be parsed as UTF-8
        // We'll use a valid header construction but with an empty value to test the fallback
        let request = Request::builder()
            .method(Method::GET)
            .uri("/test")
            .header("x-trace-id", "") // Empty trace ID should trigger fallback
            .body(Empty::<Bytes>::new())
            .unwrap();

        let (_, request_info) = middleware.process(request, None).await;

        // Should generate new trace ID when existing one is empty/invalid
        assert!(!request_info.trace_id.is_empty());
        assert_ne!(request_info.trace_id, "");
    }

    #[test]
    fn test_log_response_basic() {
        let config = create_test_config();
        let middleware = LoggingMiddleware::new(config);

        let response = Response::builder()
            .status(200)
            .body(Empty::<Bytes>::new())
            .unwrap();

        let request_info = RequestInfo {
            trace_id: "test-trace-123".to_string(),
            method: "GET".to_string(),
            path: "/test".to_string(),
            remote_addr: "192.168.1.1".to_string(),
            user_agent: "test-agent".to_string(),
            start_time_ms: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis(),
        };

        // This should not panic
        middleware.log_response(&response, &request_info, Some(Duration::from_millis(50)));
    }

    #[test]
    fn test_log_response_structured() {
        let config = create_test_config_structured();
        let middleware = LoggingMiddleware::new(config);

        let response = Response::builder()
            .status(404)
            .body(Empty::<Bytes>::new())
            .unwrap();

        let request_info = RequestInfo {
            trace_id: "test-trace-456".to_string(),
            method: "POST".to_string(),
            path: "/api/users".to_string(),
            remote_addr: "10.0.0.1".to_string(),
            user_agent: "curl/7.68.0".to_string(),
            start_time_ms: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis(),
        };

        // This should not panic
        middleware.log_response(&response, &request_info, None);
    }

    #[test]
    fn test_log_response_no_upstream_duration() {
        let config = create_test_config();
        let middleware = LoggingMiddleware::new(config);

        let response = Response::builder()
            .status(500)
            .body(Empty::<Bytes>::new())
            .unwrap();

        let request_info = RequestInfo {
            trace_id: "test-trace-789".to_string(),
            method: "DELETE".to_string(),
            path: "/api/resource/123".to_string(),
            remote_addr: "172.16.0.1".to_string(),
            user_agent: "Mozilla/5.0".to_string(),
            start_time_ms: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis(),
        };

        // This should not panic and handle None upstream duration
        middleware.log_response(&response, &request_info, None);
    }

    // Mock future for testing TracedResponseFuture
    struct MockResponseFuture {
        response: Option<Result<Response<Empty<Bytes>>, &'static str>>,
    }

    impl MockResponseFuture {
        fn new_ok(response: Response<Empty<Bytes>>) -> Self {
            Self {
                response: Some(Ok(response)),
            }
        }

        fn new_err(error: &'static str) -> Self {
            Self {
                response: Some(Err(error)),
            }
        }
    }

    impl Future for MockResponseFuture {
        type Output = Result<Response<Empty<Bytes>>, &'static str>;

        fn poll(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
            Poll::Ready(self.response.take().unwrap())
        }
    }

    impl Unpin for MockResponseFuture {}

    #[tokio::test]
    async fn test_traced_response_future_success_with_trace_id() {
        let response = Response::builder()
            .status(200)
            .body(Empty::<Bytes>::new())
            .unwrap();

        let future = MockResponseFuture::new_ok(response);
        let traced_future = future.with_trace_id(
            "test-trace-123".to_string(),
            "x-trace-id".to_string(),
            true,
        );

        let result = traced_future.await;
        assert!(result.is_ok());

        let response = result.unwrap();
        assert_eq!(response.status(), 200);
        assert!(response.headers().contains_key("x-trace-id"));
        assert_eq!(
            response.headers().get("x-trace-id").unwrap(),
            "test-trace-123"
        );
    }

    #[tokio::test]
    async fn test_traced_response_future_success_without_trace_id() {
        let response = Response::builder()
            .status(201)
            .body(Empty::<Bytes>::new())
            .unwrap();

        let future = MockResponseFuture::new_ok(response);
        let traced_future = future.with_trace_id(
            "test-trace-456".to_string(),
            "x-trace-id".to_string(),
            false, // Don't include trace ID
        );

        let result = traced_future.await;
        assert!(result.is_ok());

        let response = result.unwrap();
        assert_eq!(response.status(), 201);
        assert!(!response.headers().contains_key("x-trace-id"));
    }

    #[tokio::test]
    async fn test_traced_response_future_error() {
        let future = MockResponseFuture::new_err("test error");
        let traced_future = future.with_trace_id(
            "test-trace-789".to_string(),
            "x-trace-id".to_string(),
            true,
        );

        let result = traced_future.await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "test error");
    }

    #[tokio::test]
    async fn test_traced_response_future_invalid_header_name() {
        let response = Response::builder()
            .status(200)
            .body(Empty::<Bytes>::new())
            .unwrap();

        let future = MockResponseFuture::new_ok(response);
        let traced_future = future.with_trace_id(
            "test-trace-123".to_string(),
            "invalid header name with spaces".to_string(), // Invalid header name
            true,
        );

        let result = traced_future.await;
        assert!(result.is_ok());

        let response = result.unwrap();
        // Should fallback to x-trace-id header
        assert!(response.headers().contains_key("x-trace-id"));
    }

    #[tokio::test]
    async fn test_traced_response_future_invalid_header_value() {
        let response = Response::builder()
            .status(200)
            .body(Empty::<Bytes>::new())
            .unwrap();

        let future = MockResponseFuture::new_ok(response);
        let traced_future = future.with_trace_id(
            "\x00\x01\x02".to_string(), // Invalid header value
            "x-trace-id".to_string(),
            true,
        );

        let result = traced_future.await;
        assert!(result.is_ok());

        let response = result.unwrap();
        assert!(response.headers().contains_key("x-trace-id"));
        // Should fallback to "invalid-trace-id"
        assert_eq!(
            response.headers().get("x-trace-id").unwrap(),
            "invalid-trace-id"
        );
    }
}
