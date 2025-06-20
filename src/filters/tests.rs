// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

#[cfg(test)]
mod tests {
    use bytes::Bytes;
    use futures_util::StreamExt;
    use http_body_util::BodyExt;
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
}
