// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

#[cfg(test)]
mod tests {
    use crate::{
        HttpMethod, ProxyRequest,
        LoggingFilter, HeaderFilter, TimeoutFilter,
        PathRewriteFilter, PathRewriteFilterConfig
    };
    use crate::filters::{
        LoggingFilterConfig, HeaderFilterConfig, TimeoutFilterConfig
    };
    use crate::core::{RequestContext, Filter};
    use reqwest::Body;
    use std::sync::Arc;
    use tokio::sync::RwLock;
    use std::collections::HashMap;

    // Helper function to create a test request
    fn create_test_request(method: HttpMethod, path: &str, headers: Vec<(&'static str, &'static str)>, body: Vec<u8>) -> ProxyRequest {
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
        }
    }

    #[tokio::test]
    async fn test_logging_filter() {
        // Create a test request
        let request = create_test_request(
            HttpMethod::Get,
            "/test",
            vec![("content-type", "application/json")],
            b"{\"test\": \"value\"}".to_vec()
        );

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
            Vec::new()
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
            Vec::new()
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
            Vec::new()
        );

        // Create a path rewrite filter
        let config = PathRewriteFilterConfig {
            pattern: "^/api/(.*)$".to_string(),
            replacement: "/v2/$1".to_string(),
            rewrite_request: true,
            rewrite_response: false,
        };
        let filter = PathRewriteFilter::new(config);

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
            Vec::new()
        );

        // Create a path rewrite filter
        let config = PathRewriteFilterConfig {
            pattern: "^/api/(.*)$".to_string(),
            replacement: "/v2/$1".to_string(),
            rewrite_request: true,
            rewrite_response: false,
        };
        let filter = PathRewriteFilter::new(config);

        // Apply the filter
        let filtered_request = filter.pre_filter(request).await.unwrap();

        // Verify path was not changed
        assert_eq!(filtered_request.path, "/other/path");
    }
}
