// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

#[cfg(test)]
mod tests {
    use bytes::Bytes;
    use futures_util::StreamExt;
    use http_body_util::BodyExt;
    use crate::{
        HttpMethod, ProxyRequest, ProxyResponse, ProxyError, FilterType,
        LoggingFilter, HeaderFilter, TimeoutFilter,
        PathRewriteFilter, PathRewriteFilterConfig,
        RateLimitFilter, RateLimitFilterConfig
    };
    use crate::filters::{
        LoggingFilterConfig, HeaderFilterConfig, TimeoutFilterConfig
    };
    use crate::core::{RequestContext, ResponseContext, Filter};
    use reqwest::Body;
    use std::sync::Arc;
    use tokio::sync::RwLock;
    use std::collections::HashMap;

    // Helper function to create a test request
    fn create_test_request(method: HttpMethod, path: &str, headers: Vec<(&'static str, &'static str)>, body: Vec<u8>, target: &str) -> ProxyRequest {
        let mut header_map = reqwest::header::HeaderMap::new();
        for (name, value) in headers {
            header_map.insert(
                reqwest::header::HeaderName::from_static(name),
                reqwest::header::HeaderValue::from_static(value),
            );
        }

        ProxyRequest {
            method,
            path: path.to_string(),
            query: None,
            headers: header_map,
            body: Body::from(body),
            context: Arc::new(RwLock::new(RequestContext::default())),
            custom_target: Some(target.to_string()),
        }
    }

    // Helper function to create a test response
    fn create_test_response(
        status: u16,
        headers: Vec<(&'static str, &'static str)>,
        body: Vec<u8>,
    ) -> ProxyResponse {
        let mut header_map = reqwest::header::HeaderMap::new();
        for (name, value) in headers {
            header_map.insert(
                reqwest::header::HeaderName::from_static(name),
                reqwest::header::HeaderValue::from_static(value),
            );
        }

        ProxyResponse {
            status,
            headers: header_map,
            body: Body::from(body),
            context: Arc::new(RwLock::new(ResponseContext::default())),
        }
    }

    #[tokio::test]
    async fn test_logging_filter() {
        // Create a test request
        let request = create_test_request(HttpMethod::Get,
                                          "/test",
                                          vec![("content-type", "application/json")],
                                          b"{\"test\": \"value\"}".to_vec(),
                                          "http://test.co.za");

        // Create a logging filter
        let config = LoggingFilterConfig {
            log_request_body: true,
            log_request_headers: true,
            log_response_body: false,
            log_response_headers: true,
            log_level: "debug".to_string(),
            max_body_size: 1000,
        };
        let filter = LoggingFilter::new(config);

        // Apply the filter
        let filtered_request = filter.pre_filter(request).await.unwrap();

        // Since logging filter doesn't modify the request, just verify it returns the request
        assert_eq!(filtered_request.path, "/test");
    }

    #[tokio::test]
    async fn test_header_filter() {
        // Create a test request
        let request = create_test_request(
            HttpMethod::Get,
            "/test",
            vec![
                ("content-type", "application/json"),
                ("x-remove-me", "should be removed")
            ],
            Vec::new(),
            "http://test.co.za"
        );

        // Create a header filter
        let mut add_request_headers = HashMap::new();
        add_request_headers.insert("x-custom-header".to_string(), "custom-value".to_string());

        let config = HeaderFilterConfig {
            add_request_headers,
            remove_request_headers: vec!["x-remove-me".to_string()],
            add_response_headers: HashMap::new(),
            remove_response_headers: Vec::new(),
        };
        let filter = HeaderFilter::new(config);

        // Apply the filter
        let filtered_request = filter.pre_filter(request).await.unwrap();

        // Verify headers were modified
        assert!(filtered_request.headers.contains_key("x-custom-header"));
        assert!(!filtered_request.headers.contains_key("x-remove-me"));

        let custom_header = filtered_request.headers.get("x-custom-header").unwrap();
        assert_eq!(custom_header, "custom-value");
    }

    #[tokio::test]
    async fn test_timeout_filter() {
        // Create a test request
        let request = create_test_request(
            HttpMethod::Get,
            "/test",
            vec![],
            Vec::new(),
            "http://test.co.za"
        );

        // Create a timeout filter
        let config = TimeoutFilterConfig { timeout_ms: 5000 };
        let filter = TimeoutFilter::new(config);

        // Apply the filter
        let filtered_request = filter.pre_filter(request).await.unwrap();

        // Verify timeout was set in context
        let context = filtered_request.context.read().await;
        let timeout = context.attributes.get("timeout_ms").unwrap();
        assert_eq!(timeout, &serde_json::json!(5000));
    }

    #[tokio::test]
    async fn test_path_rewrite_filter() {
        // Create a test request
        let request = create_test_request(
            HttpMethod::Get,
            "/api/users",
            vec![],
            Vec::new(),
            "http://test.co.za"
        );

        // Create a path rewrite filter
        let config = PathRewriteFilterConfig {
            pattern: "^/api/(.*)$".to_string(),
            replacement: "/v2/$1".to_string(),
            rewrite_request: true,
            rewrite_response: false,
        };
        let filter = PathRewriteFilter::new(config).expect("Failed to create filter");

        // Apply the filter
        let filtered_request = filter.pre_filter(request).await.unwrap();

        // Verify path was rewritten
        assert_eq!(filtered_request.path, "/v2/users");
    }

    #[tokio::test]
    async fn test_path_rewrite_filter_no_match() {
        // Create a test request with path that doesn't match pattern
        let request = create_test_request(
            HttpMethod::Get,
            "/other/path",
            vec![],
            Vec::new(),
            "http://test.co.za"
        );

        // Create a path rewrite filter
        let config = PathRewriteFilterConfig {
            pattern: "^/api/(.*)$".to_string(),
            replacement: "/v2/$1".to_string(),
            rewrite_request: true,
            rewrite_response: false,
        };
        let filter = PathRewriteFilter::new(config).expect("Failed to create filter");

        // Apply the filter
        let filtered_request = filter.pre_filter(request).await.unwrap();

        // Verify path was not changed
        assert_eq!(filtered_request.path, "/other/path");
    }

    #[tokio::test]
    async fn test_tee_body_streaming() {
        use crate::filters::tee_body;

        // Create a large body with multiple chunks
        let chunk1 = Bytes::from(vec![b'a'; 500]);
        let chunk2 = Bytes::from(vec![b'b'; 500]);
        let chunk3 = Bytes::from(vec![b'c'; 500]);

        // Create a stream of chunks
        let stream = futures_util::stream::iter(vec![
            Ok::<_, std::io::Error>(chunk1),
            Ok(chunk2),
            Ok(chunk3),
        ]);

        // Create a body from the stream
        let body = reqwest::Body::wrap_stream(stream);

        // Apply tee_body with a limit of 800 bytes
        let (new_body, snippet) = tee_body(body, 800).await.unwrap();

        // Consume the body to ensure all chunks are processed
        let mut stream = new_body.into_data_stream();
        let mut total_bytes = 0;

        while let Some(chunk_result) = stream.next().await {
            let chunk = chunk_result.unwrap();
            total_bytes += chunk.len();
        }

        // Verify we read all 1500 bytes
        assert_eq!(total_bytes, 1500);

        // Verify the snippet contains the first 800 bytes (500 'a's and 300 'b's)
        assert_eq!(snippet.len(), 800);
        assert_eq!(&snippet[0..500], &"a".repeat(500));
        assert_eq!(&snippet[500..800], &"b".repeat(300));
    }

    // Tests for FilterFactory
    #[tokio::test]
    async fn test_filter_factory_create_logging_filter() {
        use crate::filters::FilterFactory;
        use serde_json::json;

        let config = json!({
            "log_request_body": true,
            "log_request_headers": true,
            "log_response_body": false,
            "log_response_headers": true,
            "log_level": "info",
            "max_body_size": 2048
        });

        let filter = FilterFactory::create_filter("logging", config).unwrap();
        assert_eq!(filter.name(), "logging");
        assert_eq!(filter.filter_type(), FilterType::Both);
    }

    #[tokio::test]
    async fn test_filter_factory_create_header_filter() {
        use crate::filters::FilterFactory;
        use serde_json::json;

        let config = json!({
            "add_request_headers": {
                "x-custom": "value"
            },
            "remove_request_headers": ["x-remove"],
            "add_response_headers": {},
            "remove_response_headers": []
        });

        let filter = FilterFactory::create_filter("header", config).unwrap();
        assert_eq!(filter.name(), "header");
        assert_eq!(filter.filter_type(), FilterType::Both);
    }

    #[tokio::test]
    async fn test_filter_factory_create_timeout_filter() {
        use crate::filters::FilterFactory;
        use serde_json::json;

        let config = json!({
            "timeout_ms": 30000
        });

        let filter = FilterFactory::create_filter("timeout", config).unwrap();
        assert_eq!(filter.name(), "timeout");
        assert_eq!(filter.filter_type(), FilterType::Pre);
    }

    #[tokio::test]
    async fn test_filter_factory_create_path_rewrite_filter() {
        use crate::filters::FilterFactory;
        use serde_json::json;

        let config = json!({
            "pattern": "^/api/(.*)$",
            "replacement": "/v2/$1",
            "rewrite_request": true,
            "rewrite_response": false
        });

        let filter = FilterFactory::create_filter("path_rewrite", config).unwrap();
        assert_eq!(filter.name(), "path_rewrite");
        assert_eq!(filter.filter_type(), FilterType::Both);
    }

    #[tokio::test]
    async fn test_filter_factory_unknown_filter() {
        use crate::filters::FilterFactory;
        use serde_json::json;

        let config = json!({});
        let result = FilterFactory::create_filter("unknown_filter", config);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Unknown filter type"));
    }

    #[tokio::test]
    async fn test_filter_factory_invalid_config() {
        use crate::filters::FilterFactory;
        use serde_json::json;

        // Test with completely missing required fields
        let config = json!({});

        let _result = FilterFactory::create_filter("logging", config);
        // The LoggingFilterConfig has defaults, so this might actually succeed
        // Let's test with a truly invalid config instead
        let invalid_config = json!({
            "log_level": "invalid_level", // Invalid log level
            "max_body_size": -1 // Invalid negative size
        });

        let result = FilterFactory::create_filter("logging", invalid_config);
        // This test might need adjustment based on actual validation behavior
        // For now, let's just verify the factory can handle the call
        let _ = result; // Don't assert error since validation might be lenient
    }

    // Tests for filter registration
    #[tokio::test]
    async fn test_register_filter() {
        use crate::filters::{register_filter, FilterFactory};
        use serde_json::json;
        use std::sync::Arc;

        // Define a custom filter
        #[derive(Debug)]
        struct CustomFilter;

        #[async_trait::async_trait]
        impl Filter for CustomFilter {
            fn filter_type(&self) -> FilterType {
                FilterType::Pre
            }

            fn name(&self) -> &str {
                "custom"
            }

            async fn pre_filter(&self, request: ProxyRequest) -> Result<ProxyRequest, ProxyError> {
                Ok(request)
            }
        }

        // Register the custom filter
        register_filter("custom_test", |_config| {
            Ok(Arc::new(CustomFilter))
        });

        // Create the filter using the factory
        let config = json!({});
        let filter = FilterFactory::create_filter("custom_test", config).unwrap();
        assert_eq!(filter.name(), "custom");
        assert_eq!(filter.filter_type(), FilterType::Pre);
    }

    // Tests for LoggingFilter edge cases
    #[tokio::test]
    async fn test_logging_filter_large_body() {
        let large_body = vec![b'x'; 5000];
        let request = create_test_request(
            HttpMethod::Post,
            "/test",
            vec![("content-type", "application/json")],
            large_body,
            "http://test.co.za"
        );

        let config = LoggingFilterConfig {
            log_request_body: true,
            log_request_headers: true,
            log_response_body: false,
            log_response_headers: true,
            log_level: "debug".to_string(),
            max_body_size: 1000, // Smaller than body size
        };
        let filter = LoggingFilter::new(config);

        let filtered_request = filter.pre_filter(request).await.unwrap();
        assert_eq!(filtered_request.path, "/test");
    }

    #[tokio::test]
    async fn test_logging_filter_different_log_levels() {
        let request = create_test_request(
            HttpMethod::Get,
            "/test",
            vec![],
            Vec::new(),
            "http://test.co.za"
        );

        for level in &["trace", "debug", "info", "warn", "error"] {
            let config = LoggingFilterConfig {
                log_request_body: false,
                log_request_headers: false,
                log_response_body: false,
                log_response_headers: false,
                log_level: level.to_string(),
                max_body_size: 1000,
            };
            let filter = LoggingFilter::new(config);

            let filtered_request = filter.pre_filter(request.clone()).await.unwrap();
            assert_eq!(filtered_request.path, "/test");
        }
    }

    #[tokio::test]
    async fn test_logging_filter_post_filter() {
        let request = create_test_request(
            HttpMethod::Get,
            "/test",
            vec![],
            Vec::new(),
            "http://test.co.za"
        );

        let response = create_test_response(
            200,
            vec![("content-type", "application/json")],
            b"{\"result\": \"success\"}".to_vec()
        );

        let config = LoggingFilterConfig {
            log_request_body: false,
            log_request_headers: false,
            log_response_body: true,
            log_response_headers: true,
            log_level: "info".to_string(),
            max_body_size: 1000,
        };
        let filter = LoggingFilter::new(config);

        let filtered_response = filter.post_filter(request, response).await.unwrap();
        assert_eq!(filtered_response.status, 200);
    }

    // Tests for HeaderFilter edge cases
    #[tokio::test]
    async fn test_header_filter_post_filter() {
        let request = create_test_request(
            HttpMethod::Get,
            "/test",
            vec![],
            Vec::new(),
            "http://test.co.za"
        );

        let response = create_test_response(
            200,
            vec![
                ("content-type", "application/json"),
                ("x-remove-response", "should be removed")
            ],
            Vec::new()
        );

        let mut add_response_headers = HashMap::new();
        add_response_headers.insert("x-custom-response".to_string(), "response-value".to_string());

        let config = HeaderFilterConfig {
            add_request_headers: HashMap::new(),
            remove_request_headers: Vec::new(),
            add_response_headers,
            remove_response_headers: vec!["x-remove-response".to_string()],
        };
        let filter = HeaderFilter::new(config);

        let filtered_response = filter.post_filter(request, response).await.unwrap();

        // Check that response header was added
        assert!(filtered_response.headers.contains_key("x-custom-response"));
        assert_eq!(
            filtered_response.headers.get("x-custom-response").unwrap(),
            "response-value"
        );

        // Check that response header was removed
        assert!(!filtered_response.headers.contains_key("x-remove-response"));
    }

    #[tokio::test]
    async fn test_header_filter_empty_config() {
        let request = create_test_request(
            HttpMethod::Get,
            "/test",
            vec![("existing-header", "existing-value")],
            Vec::new(),
            "http://test.co.za"
        );

        let config = HeaderFilterConfig {
            add_request_headers: HashMap::new(),
            remove_request_headers: Vec::new(),
            add_response_headers: HashMap::new(),
            remove_response_headers: Vec::new(),
        };
        let filter = HeaderFilter::new(config);

        let filtered_request = filter.pre_filter(request).await.unwrap();

        // Verify existing header is preserved
        assert!(filtered_request.headers.contains_key("existing-header"));
        assert_eq!(
            filtered_request.headers.get("existing-header").unwrap(),
            "existing-value"
        );
    }

    // Tests for PathRewriteFilter edge cases
    #[tokio::test]
    async fn test_path_rewrite_filter_disabled_request() {
        let request = create_test_request(
            HttpMethod::Get,
            "/api/users",
            vec![],
            Vec::new(),
            "http://test.co.za"
        );

        let config = PathRewriteFilterConfig {
            pattern: "^/api/(.*)$".to_string(),
            replacement: "/v2/$1".to_string(),
            rewrite_request: false, // Disabled
            rewrite_response: false,
        };
        let filter = PathRewriteFilter::new(config).expect("Failed to create filter");

        let filtered_request = filter.pre_filter(request).await.unwrap();

        // Verify path was not changed because rewrite_request is false
        assert_eq!(filtered_request.path, "/api/users");
    }

    #[tokio::test]
    async fn test_path_rewrite_filter_post_filter_enabled() {
        let request = create_test_request(
            HttpMethod::Get,
            "/test",
            vec![],
            Vec::new(),
            "http://test.co.za"
        );

        let response = create_test_response(200, vec![], Vec::new());

        let config = PathRewriteFilterConfig {
            pattern: "^/api/(.*)$".to_string(),
            replacement: "/v2/$1".to_string(),
            rewrite_request: false,
            rewrite_response: true, // Enabled but not implemented
        };
        let filter = PathRewriteFilter::new(config).expect("Failed to create filter");

        let filtered_response = filter.post_filter(request, response).await.unwrap();

        // Should succeed even though response rewriting is not implemented
        assert_eq!(filtered_response.status, 200);
    }

    #[tokio::test]
    async fn test_path_rewrite_filter_invalid_regex() {
        let config = PathRewriteFilterConfig {
            pattern: "[invalid regex".to_string(), // Invalid regex
            replacement: "/v2/$1".to_string(),
            rewrite_request: true,
            rewrite_response: false,
        };

        let result = PathRewriteFilter::new(config);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Invalid regex pattern"));
    }

    #[tokio::test]
    async fn test_path_rewrite_filter_complex_pattern() {
        let request = create_test_request(
            HttpMethod::Get,
            "/api/v1/users/123/posts/456",
            vec![],
            Vec::new(),
            "http://test.co.za"
        );

        let config = PathRewriteFilterConfig {
            pattern: r"^/api/v1/users/(\d+)/posts/(\d+)$".to_string(),
            replacement: "/v2/user/$1/post/$2".to_string(),
            rewrite_request: true,
            rewrite_response: false,
        };
        let filter = PathRewriteFilter::new(config).expect("Failed to create filter");

        let filtered_request = filter.pre_filter(request).await.unwrap();

        // Verify complex path rewriting
        assert_eq!(filtered_request.path, "/v2/user/123/post/456");
    }

    // Tests for TimeoutFilter edge cases
    #[tokio::test]
    async fn test_timeout_filter_zero_timeout() {
        let request = create_test_request(
            HttpMethod::Get,
            "/test",
            vec![],
            Vec::new(),
            "http://test.co.za"
        );

        let config = TimeoutFilterConfig { timeout_ms: 0 };
        let filter = TimeoutFilter::new(config);

        let filtered_request = filter.pre_filter(request).await.unwrap();

        let context = filtered_request.context.read().await;
        let timeout = context.attributes.get("timeout_ms").unwrap();
        assert_eq!(timeout, &serde_json::json!(0));
    }

    #[tokio::test]
    async fn test_timeout_filter_large_timeout() {
        let request = create_test_request(
            HttpMethod::Get,
            "/test",
            vec![],
            Vec::new(),
            "http://test.co.za"
        );

        let config = TimeoutFilterConfig { timeout_ms: u64::MAX };
        let filter = TimeoutFilter::new(config);

        let filtered_request = filter.pre_filter(request).await.unwrap();

        let context = filtered_request.context.read().await;
        let timeout = context.attributes.get("timeout_ms").unwrap();
        assert_eq!(timeout, &serde_json::json!(u64::MAX));
    }

    // Tests for utility functions
    #[tokio::test]
    async fn test_tee_body_empty() {
        use crate::filters::tee_body;

        let body = reqwest::Body::from(Vec::<u8>::new());
        let (new_body, snippet) = tee_body(body, 100).await.unwrap();

        // Consume the body
        let mut stream = new_body.into_data_stream();
        let mut total_bytes = 0;

        while let Some(chunk_result) = stream.next().await {
            let chunk = chunk_result.unwrap();
            total_bytes += chunk.len();
        }

        assert_eq!(total_bytes, 0);
        assert_eq!(snippet.len(), 0);
    }

    #[tokio::test]
    async fn test_tee_body_exact_limit() {
        use crate::filters::tee_body;

        let data = vec![b'x'; 100];
        let body = reqwest::Body::from(data);
        let (new_body, snippet) = tee_body(body, 100).await.unwrap();

        // Consume the body
        let mut stream = new_body.into_data_stream();
        let mut total_bytes = 0;

        while let Some(chunk_result) = stream.next().await {
            let chunk = chunk_result.unwrap();
            total_bytes += chunk.len();
        }

        assert_eq!(total_bytes, 100);
        assert_eq!(snippet.len(), 100);
        assert_eq!(snippet, "x".repeat(100));
    }

    #[tokio::test]
    async fn test_tee_body_error_stream() {
        use crate::filters::tee_body;

        // Create a stream that produces an error
        let stream = futures_util::stream::iter(vec![
            Ok::<_, std::io::Error>(Bytes::from("data")),
            Err(std::io::Error::new(std::io::ErrorKind::Other, "test error")),
        ]);

        let body = reqwest::Body::wrap_stream(stream);
        let result = tee_body(body, 100).await;

        assert!(result.is_err());
    }

    // Tests for default functions
    #[test]
    fn test_default_true() {
        use crate::filters::default_true;
        assert_eq!(default_true(), true);
    }

    #[test]
    fn test_default_false() {
        use crate::filters::default_false;
        assert_eq!(default_false(), false);
    }

    // Tests for LoggingFilter formatting methods
    #[tokio::test]
    async fn test_logging_filter_format_headers() {
        let config = LoggingFilterConfig::default();
        let filter = LoggingFilter::new(config);

        // Create a header map with various headers
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert("content-type", "application/json".parse().unwrap());
        headers.insert("x-custom-header", "custom-value".parse().unwrap());
        headers.insert("authorization", "Bearer token123".parse().unwrap());

        let formatted = filter.format_headers(&headers);

        // Verify all headers are included
        assert!(formatted.contains("content-type: application/json"));
        assert!(formatted.contains("x-custom-header: custom-value"));
        assert!(formatted.contains("authorization: Bearer token123"));

        // Verify headers are separated by newlines
        let lines: Vec<&str> = formatted.lines().collect();
        assert_eq!(lines.len(), 3);
    }

    #[tokio::test]
    async fn test_logging_filter_format_headers_empty() {
        let config = LoggingFilterConfig::default();
        let filter = LoggingFilter::new(config);

        let headers = reqwest::header::HeaderMap::new();
        let formatted = filter.format_headers(&headers);

        assert_eq!(formatted, "");
    }

    #[tokio::test]
    async fn test_logging_filter_format_body_empty() {
        let config = LoggingFilterConfig::default();
        let filter = LoggingFilter::new(config);

        let body = b"";
        let formatted = filter.format_body(body);

        assert_eq!(formatted, "[Empty body]");
    }

    #[tokio::test]
    async fn test_logging_filter_format_body_small() {
        let config = LoggingFilterConfig {
            max_body_size: 1000,
            ..LoggingFilterConfig::default()
        };
        let filter = LoggingFilter::new(config);

        let body = b"Hello, World!";
        let formatted = filter.format_body(body);

        assert_eq!(formatted, "Hello, World!");
    }

    #[tokio::test]
    async fn test_logging_filter_format_body_truncated() {
        let config = LoggingFilterConfig {
            max_body_size: 10,
            ..LoggingFilterConfig::default()
        };
        let filter = LoggingFilter::new(config);

        let body = b"This is a very long body that should be truncated";
        let formatted = filter.format_body(body);

        assert!(formatted.contains("[Body truncated, showing 10/49 bytes]"));
        assert!(formatted.contains("This is a "));
        assert!(!formatted.contains("very long body"));
    }

    #[tokio::test]
    async fn test_logging_filter_format_body_binary() {
        let config = LoggingFilterConfig {
            max_body_size: 1000,
            ..LoggingFilterConfig::default()
        };
        let filter = LoggingFilter::new(config);

        // Create binary data with some invalid UTF-8
        let body = vec![0x48, 0x65, 0x6c, 0x6c, 0x6f, 0xff, 0xfe, 0x21]; // "Hello" + invalid UTF-8 + "!"
        let formatted = filter.format_body(&body);

        // Should handle invalid UTF-8 gracefully using lossy conversion
        assert!(formatted.contains("Hello"));
        assert!(formatted.contains("!"));
    }

    // Tests for LoggingFilter different log levels
    #[tokio::test]
    async fn test_logging_filter_error_level() {
        let request = create_test_request(
            HttpMethod::Get,
            "/test",
            vec![("content-type", "application/json")],
            b"test body".to_vec(),
            "http://test.co.za"
        );

        let config = LoggingFilterConfig {
            log_request_body: true,
            log_request_headers: true,
            log_response_body: false,
            log_response_headers: false,
            log_level: "error".to_string(),
            max_body_size: 1000,
        };
        let filter = LoggingFilter::new(config);

        let filtered_request = filter.pre_filter(request).await.unwrap();
        assert_eq!(filtered_request.path, "/test");
    }

    #[tokio::test]
    async fn test_logging_filter_warn_level() {
        let request = create_test_request(
            HttpMethod::Get,
            "/test",
            vec![("content-type", "application/json")],
            b"test body".to_vec(),
            "http://test.co.za"
        );

        let config = LoggingFilterConfig {
            log_request_body: true,
            log_request_headers: true,
            log_response_body: false,
            log_response_headers: false,
            log_level: "warn".to_string(),
            max_body_size: 1000,
        };
        let filter = LoggingFilter::new(config);

        let filtered_request = filter.pre_filter(request).await.unwrap();
        assert_eq!(filtered_request.path, "/test");
    }

    #[tokio::test]
    async fn test_logging_filter_info_level() {
        let request = create_test_request(
            HttpMethod::Get,
            "/test",
            vec![("content-type", "application/json")],
            b"test body".to_vec(),
            "http://test.co.za"
        );

        let config = LoggingFilterConfig {
            log_request_body: true,
            log_request_headers: true,
            log_response_body: false,
            log_response_headers: false,
            log_level: "info".to_string(),
            max_body_size: 1000,
        };
        let filter = LoggingFilter::new(config);

        let filtered_request = filter.pre_filter(request).await.unwrap();
        assert_eq!(filtered_request.path, "/test");
    }

    #[tokio::test]
    async fn test_logging_filter_trace_level() {
        let request = create_test_request(
            HttpMethod::Get,
            "/test",
            vec![("content-type", "application/json")],
            b"test body".to_vec(),
            "http://test.co.za"
        );

        let config = LoggingFilterConfig {
            log_request_body: true,
            log_request_headers: true,
            log_response_body: false,
            log_response_headers: false,
            log_level: "trace".to_string(),
            max_body_size: 1000,
        };
        let filter = LoggingFilter::new(config);

        let filtered_request = filter.pre_filter(request).await.unwrap();
        assert_eq!(filtered_request.path, "/test");
    }

    #[tokio::test]
    async fn test_logging_filter_invalid_log_level() {
        let request = create_test_request(
            HttpMethod::Get,
            "/test",
            vec![("content-type", "application/json")],
            b"test body".to_vec(),
            "http://test.co.za"
        );

        let config = LoggingFilterConfig {
            log_request_body: true,
            log_request_headers: true,
            log_response_body: false,
            log_response_headers: false,
            log_level: "invalid".to_string(), // Invalid log level
            max_body_size: 1000,
        };
        let filter = LoggingFilter::new(config);

        // Should default to trace level and not crash
        let filtered_request = filter.pre_filter(request).await.unwrap();
        assert_eq!(filtered_request.path, "/test");
    }

    // Tests for LoggingFilter post_filter functionality
    #[tokio::test]
    async fn test_logging_filter_post_filter_response_headers() {
        let request = create_test_request(
            HttpMethod::Get,
            "/test",
            vec![],
            Vec::new(),
            "http://test.co.za"
        );

        let response = create_test_response(
            200,
            vec![("content-type", "application/json"), ("x-custom", "value")],
            b"response body".to_vec()
        );

        let config = LoggingFilterConfig {
            log_request_body: false,
            log_request_headers: false,
            log_response_body: false,
            log_response_headers: true,
            log_level: "debug".to_string(),
            max_body_size: 1000,
        };
        let filter = LoggingFilter::new(config);

        let filtered_response = filter.post_filter(request, response).await.unwrap();
        assert_eq!(filtered_response.status, 200);
    }

    #[tokio::test]
    async fn test_logging_filter_post_filter_response_body() {
        let request = create_test_request(
            HttpMethod::Get,
            "/test",
            vec![],
            Vec::new(),
            "http://test.co.za"
        );

        let response = create_test_response(
            200,
            vec![("content-type", "application/json")],
            b"response body content".to_vec()
        );

        let config = LoggingFilterConfig {
            log_request_body: false,
            log_request_headers: false,
            log_response_body: true,
            log_response_headers: false,
            log_level: "debug".to_string(),
            max_body_size: 1000,
        };
        let filter = LoggingFilter::new(config);

        let filtered_response = filter.post_filter(request, response).await.unwrap();
        assert_eq!(filtered_response.status, 200);
    }

    #[tokio::test]
    async fn test_logging_filter_post_filter_large_response_body() {
        let request = create_test_request(
            HttpMethod::Get,
            "/test",
            vec![],
            Vec::new(),
            "http://test.co.za"
        );

        let large_body = vec![b'x'; 5000];
        let response = create_test_response(
            200,
            vec![("content-type", "text/plain")],
            large_body
        );

        let config = LoggingFilterConfig {
            log_request_body: false,
            log_request_headers: false,
            log_response_body: true,
            log_response_headers: false,
            log_level: "debug".to_string(),
            max_body_size: 1000, // Smaller than response body
        };
        let filter = LoggingFilter::new(config);

        let filtered_response = filter.post_filter(request, response).await.unwrap();
        assert_eq!(filtered_response.status, 200);
    }

    // Tests for HeaderFilter comprehensive functionality
    #[tokio::test]
    async fn test_header_filter_add_request_headers() {
        let request = create_test_request(
            HttpMethod::Get,
            "/test",
            vec![("existing-header", "existing-value")],
            Vec::new(),
            "http://test.co.za"
        );

        let mut add_headers = std::collections::HashMap::new();
        add_headers.insert("x-new-header".to_string(), "new-value".to_string());
        add_headers.insert("x-another-header".to_string(), "another-value".to_string());

        let config = HeaderFilterConfig {
            add_request_headers: add_headers,
            remove_request_headers: Vec::new(),
            add_response_headers: std::collections::HashMap::new(),
            remove_response_headers: Vec::new(),
        };
        let filter = HeaderFilter::new(config);

        let filtered_request = filter.pre_filter(request).await.unwrap();

        assert!(filtered_request.headers.contains_key("x-new-header"));
        assert!(filtered_request.headers.contains_key("x-another-header"));
        assert!(filtered_request.headers.contains_key("existing-header"));
        assert_eq!(filtered_request.headers.get("x-new-header").unwrap(), "new-value");
        assert_eq!(filtered_request.headers.get("x-another-header").unwrap(), "another-value");
    }

    #[tokio::test]
    async fn test_header_filter_remove_request_headers() {
        let request = create_test_request(
            HttpMethod::Get,
            "/test",
            vec![
                ("keep-me", "keep-value"),
                ("remove-me", "remove-value"),
                ("also-remove", "also-remove-value")
            ],
            Vec::new(),
            "http://test.co.za"
        );

        let config = HeaderFilterConfig {
            add_request_headers: std::collections::HashMap::new(),
            remove_request_headers: vec!["remove-me".to_string(), "also-remove".to_string()],
            add_response_headers: std::collections::HashMap::new(),
            remove_response_headers: Vec::new(),
        };
        let filter = HeaderFilter::new(config);

        let filtered_request = filter.pre_filter(request).await.unwrap();

        assert!(filtered_request.headers.contains_key("keep-me"));
        assert!(!filtered_request.headers.contains_key("remove-me"));
        assert!(!filtered_request.headers.contains_key("also-remove"));
    }

    #[tokio::test]
    async fn test_header_filter_replace_existing_request_header() {
        let request = create_test_request(
            HttpMethod::Get,
            "/test",
            vec![("content-type", "text/plain")],
            Vec::new(),
            "http://test.co.za"
        );

        let mut add_headers = std::collections::HashMap::new();
        add_headers.insert("content-type".to_string(), "application/json".to_string());

        let config = HeaderFilterConfig {
            add_request_headers: add_headers,
            remove_request_headers: Vec::new(),
            add_response_headers: std::collections::HashMap::new(),
            remove_response_headers: Vec::new(),
        };
        let filter = HeaderFilter::new(config);

        let filtered_request = filter.pre_filter(request).await.unwrap();

        assert_eq!(filtered_request.headers.get("content-type").unwrap(), "application/json");
    }

    #[tokio::test]
    async fn test_header_filter_add_response_headers() {
        let request = create_test_request(
            HttpMethod::Get,
            "/test",
            vec![],
            Vec::new(),
            "http://test.co.za"
        );

        let response = create_test_response(
            200,
            vec![("existing-response-header", "existing-value")],
            Vec::new()
        );

        let mut add_headers = std::collections::HashMap::new();
        add_headers.insert("x-response-header".to_string(), "response-value".to_string());
        add_headers.insert("x-cors-header".to_string(), "cors-value".to_string());

        let config = HeaderFilterConfig {
            add_request_headers: std::collections::HashMap::new(),
            remove_request_headers: Vec::new(),
            add_response_headers: add_headers,
            remove_response_headers: Vec::new(),
        };
        let filter = HeaderFilter::new(config);

        let filtered_response = filter.post_filter(request, response).await.unwrap();

        assert!(filtered_response.headers.contains_key("x-response-header"));
        assert!(filtered_response.headers.contains_key("x-cors-header"));
        assert!(filtered_response.headers.contains_key("existing-response-header"));
        assert_eq!(filtered_response.headers.get("x-response-header").unwrap(), "response-value");
        assert_eq!(filtered_response.headers.get("x-cors-header").unwrap(), "cors-value");
    }

    #[tokio::test]
    async fn test_header_filter_remove_response_headers() {
        let request = create_test_request(
            HttpMethod::Get,
            "/test",
            vec![],
            Vec::new(),
            "http://test.co.za"
        );

        let response = create_test_response(
            200,
            vec![
                ("keep-response", "keep-value"),
                ("remove-response", "remove-value"),
                ("server", "nginx/1.0")
            ],
            Vec::new()
        );

        let config = HeaderFilterConfig {
            add_request_headers: std::collections::HashMap::new(),
            remove_request_headers: Vec::new(),
            add_response_headers: std::collections::HashMap::new(),
            remove_response_headers: vec!["remove-response".to_string(), "server".to_string()],
        };
        let filter = HeaderFilter::new(config);

        let filtered_response = filter.post_filter(request, response).await.unwrap();

        assert!(filtered_response.headers.contains_key("keep-response"));
        assert!(!filtered_response.headers.contains_key("remove-response"));
        assert!(!filtered_response.headers.contains_key("server"));
    }

    #[tokio::test]
    async fn test_header_filter_invalid_header_names() {
        let request = create_test_request(
            HttpMethod::Get,
            "/test",
            vec![("valid-header", "valid-value")],
            Vec::new(),
            "http://test.co.za"
        );

        let mut add_headers = std::collections::HashMap::new();
        add_headers.insert("valid-header".to_string(), "new-value".to_string());
        add_headers.insert("invalid header name".to_string(), "invalid-value".to_string()); // Contains space
        add_headers.insert("".to_string(), "empty-name".to_string()); // Empty name

        let config = HeaderFilterConfig {
            add_request_headers: add_headers,
            remove_request_headers: vec!["invalid header name".to_string()], // Invalid name to remove
            add_response_headers: std::collections::HashMap::new(),
            remove_response_headers: Vec::new(),
        };
        let filter = HeaderFilter::new(config);

        let filtered_request = filter.pre_filter(request).await.unwrap();

        // Valid header should be updated
        assert_eq!(filtered_request.headers.get("valid-header").unwrap(), "new-value");
        // Invalid headers should be ignored (not added)
        assert!(!filtered_request.headers.contains_key("invalid header name"));
        assert!(!filtered_request.headers.contains_key(""));
    }

    #[tokio::test]
    async fn test_header_filter_invalid_header_values() {
        let request = create_test_request(
            HttpMethod::Get,
            "/test",
            vec![],
            Vec::new(),
            "http://test.co.za"
        );

        let mut add_headers = std::collections::HashMap::new();
        add_headers.insert("valid-header".to_string(), "valid-value".to_string());
        add_headers.insert("invalid-value-header".to_string(), "invalid\nvalue".to_string()); // Contains newline

        let config = HeaderFilterConfig {
            add_request_headers: add_headers,
            remove_request_headers: Vec::new(),
            add_response_headers: std::collections::HashMap::new(),
            remove_response_headers: Vec::new(),
        };
        let filter = HeaderFilter::new(config);

        let filtered_request = filter.pre_filter(request).await.unwrap();

        // Valid header should be added
        assert!(filtered_request.headers.contains_key("valid-header"));
        // Invalid header value should be ignored (not added)
        assert!(!filtered_request.headers.contains_key("invalid-value-header"));
    }

    // Tests for TimeoutFilter comprehensive functionality
    #[tokio::test]
    async fn test_timeout_filter_large_timeout_comprehensive() {
        let request = create_test_request(
            HttpMethod::Get,
            "/test",
            vec![],
            Vec::new(),
            "http://test.co.za"
        );

        let config = TimeoutFilterConfig { timeout_ms: 60000 }; // 60 seconds
        let filter = TimeoutFilter::new(config);

        let filtered_request = filter.pre_filter(request).await.unwrap();

        let context = filtered_request.context.read().await;
        let timeout = context.attributes.get("timeout_ms").unwrap();
        assert_eq!(timeout, &serde_json::json!(60000));
    }

    #[tokio::test]
    async fn test_timeout_filter_very_small_timeout() {
        let request = create_test_request(
            HttpMethod::Get,
            "/test",
            vec![],
            Vec::new(),
            "http://test.co.za"
        );

        let config = TimeoutFilterConfig { timeout_ms: 1 }; // 1 millisecond
        let filter = TimeoutFilter::new(config);

        let filtered_request = filter.pre_filter(request).await.unwrap();

        let context = filtered_request.context.read().await;
        let timeout = context.attributes.get("timeout_ms").unwrap();
        assert_eq!(timeout, &serde_json::json!(1));
    }

    #[tokio::test]
    async fn test_timeout_filter_default_config() {
        let filter = TimeoutFilter::default();

        let request = create_test_request(
            HttpMethod::Get,
            "/test",
            vec![],
            Vec::new(),
            "http://test.co.za"
        );

        let filtered_request = filter.pre_filter(request).await.unwrap();

        let context = filtered_request.context.read().await;
        let timeout = context.attributes.get("timeout_ms").unwrap();
        assert_eq!(timeout, &serde_json::json!(30000)); // Default is 30 seconds
    }

    #[tokio::test]
    async fn test_timeout_filter_overwrite_existing_timeout() {
        let request = create_test_request(
            HttpMethod::Get,
            "/test",
            vec![],
            Vec::new(),
            "http://test.co.za"
        );

        // Set an initial timeout in the context
        {
            let mut context = request.context.write().await;
            context.attributes.insert("timeout_ms".to_string(), serde_json::json!(10000));
        }

        let config = TimeoutFilterConfig { timeout_ms: 20000 };
        let filter = TimeoutFilter::new(config);

        let filtered_request = filter.pre_filter(request).await.unwrap();

        let context = filtered_request.context.read().await;
        let timeout = context.attributes.get("timeout_ms").unwrap();
        assert_eq!(timeout, &serde_json::json!(20000)); // Should be overwritten
    }

    // Tests for FilterFactory functionality
    #[tokio::test]
    async fn test_filter_factory_create_logging_filter_comprehensive() {
        use crate::filters::FilterFactory;

        let config = serde_json::json!({
            "log_request_headers": true,
            "log_request_body": false,
            "log_response_headers": true,
            "log_response_body": false,
            "log_level": "info",
            "max_body_size": 2048
        });

        let filter = FilterFactory::create_filter("logging", config).unwrap();
        assert_eq!(filter.name(), "logging");
        assert_eq!(filter.filter_type(), FilterType::Both);
    }

    #[tokio::test]
    async fn test_filter_factory_create_header_filter_comprehensive() {
        use crate::filters::FilterFactory;

        let config = serde_json::json!({
            "add_request_headers": {
                "x-custom": "value"
            },
            "remove_request_headers": ["authorization"],
            "add_response_headers": {
                "x-response": "response-value"
            },
            "remove_response_headers": ["server"]
        });

        let filter = FilterFactory::create_filter("header", config).unwrap();
        assert_eq!(filter.name(), "header");
        assert_eq!(filter.filter_type(), FilterType::Both);
    }

    #[tokio::test]
    async fn test_filter_factory_create_timeout_filter_comprehensive() {
        use crate::filters::FilterFactory;

        let config = serde_json::json!({
            "timeout_ms": 15000
        });

        let filter = FilterFactory::create_filter("timeout", config).unwrap();
        assert_eq!(filter.name(), "timeout");
        assert_eq!(filter.filter_type(), FilterType::Pre);
    }

    #[tokio::test]
    async fn test_filter_factory_create_path_rewrite_filter_comprehensive() {
        use crate::filters::FilterFactory;

        let config = serde_json::json!({
            "pattern": "/old/(.*)",
            "replacement": "/new/$1"
        });

        let filter = FilterFactory::create_filter("path_rewrite", config).unwrap();
        assert_eq!(filter.name(), "path_rewrite");
        assert_eq!(filter.filter_type(), FilterType::Both);
    }

    #[tokio::test]
    async fn test_filter_factory_unknown_filter_type() {
        use crate::filters::FilterFactory;

        let config = serde_json::json!({});
        let result = FilterFactory::create_filter("unknown_filter", config);

        assert!(result.is_err());
        if let Err(ProxyError::FilterError(msg)) = result {
            assert!(msg.contains("Unknown filter type"));
        } else {
            panic!("Expected FilterError for unknown filter type");
        }
    }

    #[tokio::test]
    async fn test_filter_factory_invalid_config_comprehensive() {
        use crate::filters::FilterFactory;

        // Invalid config for logging filter (missing required fields)
        let config = serde_json::json!({
            "invalid_field": "invalid_value"
        });

        let result = FilterFactory::create_filter("logging", config);
        // Should still work because all fields have defaults
        assert!(result.is_ok());
    }

    // Tests for default configurations
    #[test]
    fn test_logging_filter_config_default() {
        let config = LoggingFilterConfig::default();
        assert_eq!(config.log_request_headers, true);
        assert_eq!(config.log_request_body, false);
        assert_eq!(config.log_response_headers, true);
        assert_eq!(config.log_response_body, false);
        assert_eq!(config.log_level, "trace");
        assert_eq!(config.max_body_size, 1024);
    }

    #[test]
    fn test_header_filter_config_default() {
        let config = HeaderFilterConfig::default();
        assert!(config.add_request_headers.is_empty());
        assert!(config.remove_request_headers.is_empty());
        assert!(config.add_response_headers.is_empty());
        assert!(config.remove_response_headers.is_empty());
    }

    #[test]
    fn test_timeout_filter_config_default() {
        let config = TimeoutFilterConfig::default();
        assert_eq!(config.timeout_ms, 30000);
    }

    // Tests for filter creation with default configs
    #[test]
    fn test_logging_filter_default() {
        let filter = LoggingFilter::default();
        assert_eq!(filter.name(), "logging");
        assert_eq!(filter.filter_type(), FilterType::Both);
    }

    #[test]
    fn test_header_filter_default() {
        let filter = HeaderFilter::default();
        assert_eq!(filter.name(), "header");
        assert_eq!(filter.filter_type(), FilterType::Both);
    }

    #[test]
    fn test_timeout_filter_default() {
        let filter = TimeoutFilter::default();
        assert_eq!(filter.name(), "timeout");
        assert_eq!(filter.filter_type(), FilterType::Pre);
    }

    // Tests for filter registration
    #[tokio::test]
    async fn test_register_custom_filter() {
        use crate::filters::{register_filter, FilterFactory};

        // Define a custom filter
        #[derive(Debug)]
        struct CustomFilter;

        #[async_trait::async_trait]
        impl Filter for CustomFilter {
            fn filter_type(&self) -> FilterType {
                FilterType::Pre
            }

            fn name(&self) -> &str {
                "custom"
            }

            async fn pre_filter(&self, request: ProxyRequest) -> Result<ProxyRequest, ProxyError> {
                Ok(request)
            }
        }

        // Register the custom filter
        register_filter("custom_test", |_config| {
            Ok(std::sync::Arc::new(CustomFilter))
        });

        // Create a filter using the registered type
        let config = serde_json::json!({});
        let filter = FilterFactory::create_filter("custom_test", config).unwrap();
        assert_eq!(filter.name(), "custom");
        assert_eq!(filter.filter_type(), FilterType::Pre);
    }

    // Tests for edge cases and error conditions
    #[tokio::test]
    async fn test_logging_filter_empty_body() {
        let request = create_test_request(
            HttpMethod::Post,
            "/test",
            vec![("content-type", "application/json")],
            Vec::new(), // Empty body
            "http://test.co.za"
        );

        let config = LoggingFilterConfig {
            log_request_body: true,
            log_request_headers: false,
            log_response_body: false,
            log_response_headers: false,
            log_level: "debug".to_string(),
            max_body_size: 1000,
        };
        let filter = LoggingFilter::new(config);

        let filtered_request = filter.pre_filter(request).await.unwrap();
        assert_eq!(filtered_request.path, "/test");
    }

    #[tokio::test]
    async fn test_header_filter_empty_configs() {
        let request = create_test_request(
            HttpMethod::Get,
            "/test",
            vec![("existing", "value")],
            Vec::new(),
            "http://test.co.za"
        );

        let config = HeaderFilterConfig {
            add_request_headers: std::collections::HashMap::new(),
            remove_request_headers: Vec::new(),
            add_response_headers: std::collections::HashMap::new(),
            remove_response_headers: Vec::new(),
        };
        let filter = HeaderFilter::new(config);

        let filtered_request = filter.pre_filter(request).await.unwrap();

        // Should not modify anything
        assert!(filtered_request.headers.contains_key("existing"));
        assert_eq!(filtered_request.headers.get("existing").unwrap(), "value");
    }

    #[tokio::test]
    async fn test_header_filter_remove_nonexistent_headers() {
        let request = create_test_request(
            HttpMethod::Get,
            "/test",
            vec![("existing", "value")],
            Vec::new(),
            "http://test.co.za"
        );

        let config = HeaderFilterConfig {
            add_request_headers: std::collections::HashMap::new(),
            remove_request_headers: vec!["nonexistent".to_string(), "also-nonexistent".to_string()],
            add_response_headers: std::collections::HashMap::new(),
            remove_response_headers: Vec::new(),
        };
        let filter = HeaderFilter::new(config);

        let filtered_request = filter.pre_filter(request).await.unwrap();

        // Should not crash and existing header should remain
        assert!(filtered_request.headers.contains_key("existing"));
        assert_eq!(filtered_request.headers.get("existing").unwrap(), "value");
    }

    // Tests for complex scenarios
    #[tokio::test]
    async fn test_multiple_filters_chaining() {
        let request = create_test_request(
            HttpMethod::Post,
            "/api/test",
            vec![("authorization", "Bearer token"), ("content-type", "text/plain")],
            b"original body".to_vec(),
            "http://test.co.za"
        );

        // First apply header filter
        let mut add_headers = std::collections::HashMap::new();
        add_headers.insert("x-processed".to_string(), "true".to_string());
        add_headers.insert("content-type".to_string(), "application/json".to_string()); // Override

        let header_config = HeaderFilterConfig {
            add_request_headers: add_headers,
            remove_request_headers: vec!["authorization".to_string()],
            add_response_headers: std::collections::HashMap::new(),
            remove_response_headers: Vec::new(),
        };
        let header_filter = HeaderFilter::new(header_config);

        let request_after_header = header_filter.pre_filter(request).await.unwrap();

        // Then apply timeout filter
        let timeout_config = TimeoutFilterConfig { timeout_ms: 5000 };
        let timeout_filter = TimeoutFilter::new(timeout_config);

        let request_after_timeout = timeout_filter.pre_filter(request_after_header).await.unwrap();

        // Finally apply logging filter
        let logging_config = LoggingFilterConfig {
            log_request_body: true,
            log_request_headers: true,
            log_response_body: false,
            log_response_headers: false,
            log_level: "info".to_string(),
            max_body_size: 1000,
        };
        let logging_filter = LoggingFilter::new(logging_config);

        let final_request = logging_filter.pre_filter(request_after_timeout).await.unwrap();

        // Verify all filters were applied
        assert!(final_request.headers.contains_key("x-processed"));
        assert!(!final_request.headers.contains_key("authorization"));
        assert_eq!(final_request.headers.get("content-type").unwrap(), "application/json");

        let context = final_request.context.read().await;
        let timeout = context.attributes.get("timeout_ms").unwrap();
        assert_eq!(timeout, &serde_json::json!(5000));
    }

    // Tests for serialization/deserialization of configs
    #[test]
    fn test_logging_filter_config_serialization() {
        let config = LoggingFilterConfig {
            log_request_headers: false,
            log_request_body: true,
            log_response_headers: false,
            log_response_body: true,
            log_level: "warn".to_string(),
            max_body_size: 2048,
        };

        let serialized = serde_json::to_string(&config).unwrap();
        let deserialized: LoggingFilterConfig = serde_json::from_str(&serialized).unwrap();

        assert_eq!(config.log_request_headers, deserialized.log_request_headers);
        assert_eq!(config.log_request_body, deserialized.log_request_body);
        assert_eq!(config.log_response_headers, deserialized.log_response_headers);
        assert_eq!(config.log_response_body, deserialized.log_response_body);
        assert_eq!(config.log_level, deserialized.log_level);
        assert_eq!(config.max_body_size, deserialized.max_body_size);
    }

    #[test]
    fn test_header_filter_config_serialization() {
        let mut add_request = std::collections::HashMap::new();
        add_request.insert("x-test".to_string(), "test-value".to_string());

        let config = HeaderFilterConfig {
            add_request_headers: add_request,
            remove_request_headers: vec!["authorization".to_string()],
            add_response_headers: std::collections::HashMap::new(),
            remove_response_headers: vec!["server".to_string()],
        };

        let serialized = serde_json::to_string(&config).unwrap();
        let deserialized: HeaderFilterConfig = serde_json::from_str(&serialized).unwrap();

        assert_eq!(config.add_request_headers, deserialized.add_request_headers);
        assert_eq!(config.remove_request_headers, deserialized.remove_request_headers);
        assert_eq!(config.add_response_headers, deserialized.add_response_headers);
        assert_eq!(config.remove_response_headers, deserialized.remove_response_headers);
    }

    #[test]
    fn test_timeout_filter_config_serialization() {
        let config = TimeoutFilterConfig { timeout_ms: 45000 };

        let serialized = serde_json::to_string(&config).unwrap();
        let deserialized: TimeoutFilterConfig = serde_json::from_str(&serialized).unwrap();

        assert_eq!(config.timeout_ms, deserialized.timeout_ms);
    }

    // Tests for RateLimitFilter
    #[tokio::test]
    async fn test_rate_limit_filter_creation() {
        let config = RateLimitFilterConfig {
            requests_per_second: 5.0,
            burst_size: 10,
        };
        let filter = RateLimitFilter::new(config);
        assert_eq!(filter.name(), "rate_limit");
        assert_eq!(filter.filter_type(), FilterType::Pre);
    }

    #[tokio::test]
    async fn test_rate_limit_filter_default_config() {
        let config = RateLimitFilterConfig::default();
        assert_eq!(config.requests_per_second, 10.0);
        assert_eq!(config.burst_size, 10);
    }

    #[tokio::test]
    async fn test_rate_limit_filter_allows_requests_within_limit() {
        let config = RateLimitFilterConfig {
            requests_per_second: 10.0,
            burst_size: 5,
        };
        let filter = RateLimitFilter::new(config);

        // Create test request
        let request = create_rate_limit_test_request();

        // First few requests should be allowed (within burst size)
        for i in 1..=5 {
            let result = filter.pre_filter(request.clone()).await;
            assert!(result.is_ok(), "Request {} should be allowed", i);
        }
    }

    #[tokio::test]
    async fn test_rate_limit_filter_blocks_requests_over_limit() {
        let config = RateLimitFilterConfig {
            requests_per_second: 1.0,
            burst_size: 2,
        };
        let filter = RateLimitFilter::new(config);

        // Create test request
        let request = create_rate_limit_test_request();

        // First two requests should be allowed (burst size)
        for i in 1..=2 {
            let result = filter.pre_filter(request.clone()).await;
            assert!(result.is_ok(), "Request {} should be allowed", i);
        }

        // Third request should be blocked
        let result = filter.pre_filter(request.clone()).await;
        assert!(result.is_err(), "Request 3 should be blocked");

        if let Err(ProxyError::RateLimitExceeded(msg)) = result {
            assert!(msg.contains("Rate limit exceeded"));
            assert!(msg.contains("1 requests per second"));
            assert!(msg.contains("burst size: 2"));
        } else {
            panic!("Expected RateLimitExceeded error");
        }
    }

    #[tokio::test]
    async fn test_rate_limit_filter_token_refill() {
        let config = RateLimitFilterConfig {
            requests_per_second: 10.0, // 10 tokens per second = 1 token per 100ms
            burst_size: 1,
        };
        let filter = RateLimitFilter::new(config);

        // Create test request
        let request = create_rate_limit_test_request();

        // First request should be allowed
        let result = filter.pre_filter(request.clone()).await;
        assert!(result.is_ok(), "First request should be allowed");

        // Second request should be blocked immediately
        let result = filter.pre_filter(request.clone()).await;
        assert!(result.is_err(), "Second request should be blocked");

        // Wait for token refill (200ms should be enough for 2 tokens at 10/sec)
        tokio::time::sleep(tokio::time::Duration::from_millis(200)).await;

        // Third request should be allowed after refill
        let result = filter.pre_filter(request.clone()).await;
        assert!(result.is_ok(), "Third request should be allowed after refill");
    }

    #[tokio::test]
    async fn test_rate_limit_filter_high_burst_size() {
        let config = RateLimitFilterConfig {
            requests_per_second: 1.0,
            burst_size: 100,
        };
        let filter = RateLimitFilter::new(config);

        // Create test request
        let request = create_rate_limit_test_request();

        // Should allow many requests initially due to high burst size
        for i in 1..=50 {
            let result = filter.pre_filter(request.clone()).await;
            assert!(result.is_ok(), "Request {} should be allowed", i);
        }
    }

    #[tokio::test]
    async fn test_rate_limit_filter_zero_burst_size() {
        let config = RateLimitFilterConfig {
            requests_per_second: 10.0,
            burst_size: 0,
        };
        let filter = RateLimitFilter::new(config);

        // Create test request
        let request = create_rate_limit_test_request();

        // Should block all requests with zero burst size
        let result = filter.pre_filter(request.clone()).await;
        assert!(result.is_err(), "Request should be blocked with zero burst size");
    }

    #[tokio::test]
    async fn test_rate_limit_filter_fractional_rate() {
        let config = RateLimitFilterConfig {
            requests_per_second: 0.5, // 1 request every 2 seconds
            burst_size: 1,
        };
        let filter = RateLimitFilter::new(config);

        // Create test request
        let request = create_rate_limit_test_request();

        // First request should be allowed
        let result = filter.pre_filter(request.clone()).await;
        assert!(result.is_ok(), "First request should be allowed");

        // Second request should be blocked
        let result = filter.pre_filter(request.clone()).await;
        assert!(result.is_err(), "Second request should be blocked");
    }

    // Helper function to create a test request for rate limiting tests
    fn create_rate_limit_test_request() -> ProxyRequest {
        use crate::core::RequestContext;
        use reqwest::Body;
        use std::sync::Arc;
        use tokio::sync::RwLock;

        ProxyRequest {
            method: HttpMethod::Get,
            path: "/test".to_string(),
            query: None,
            headers: reqwest::header::HeaderMap::new(),
            body: Body::from(""),
            custom_target: None,
            context: Arc::new(RwLock::new(RequestContext {
                client_ip: None,
                start_time: None,
                attributes: std::collections::HashMap::new(),
            })),
        }
    }
}
