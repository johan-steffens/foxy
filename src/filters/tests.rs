// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

#[cfg(test)]
mod tests {
    use reqwest::Body;
    use super::*;
    use crate::core::HttpMethod;
    use crate::core::RequestContext;
    use std::sync::Arc;
    use tokio::sync::RwLock;

    #[tokio::test]
    async fn test_logging_filter() {
        // Create a test request
        let request = ProxyRequest {
            method: HttpMethod::Get,
            path: "/test".to_string(),
            query: None,
            headers: {
                let mut map = reqwest::header::HeaderMap::new();
                map.insert(
                    reqwest::header::HeaderName::from_static("content-type"),
                    reqwest::header::HeaderValue::from_static("application/json"),
                );
                map
            },
            body: Body::from(b"{\"test\": \"value\"}".to_vec()),
            context: Arc::new(RwLock::new(RequestContext::default())),
        };

        // Create a logging filter
        let config = LoggingFilterConfig {
            log_request_body: true,
            ..LoggingFilterConfig::default()
        };
        let filter = LoggingFilter::new(config);

        // Apply the filter
        let filtered_request = filter.pre_filter(request).await.unwrap();
    }

    #[tokio::test]
    async fn test_header_filter() {
        // Create a test request
        let request = ProxyRequest {
            method: HttpMethod::Get,
            path: "/test".to_string(),
            query: None,
            headers: {
                let mut map = reqwest::header::HeaderMap::new();
                map.insert(
                    reqwest::header::HeaderName::from_static("content-type"),
                    reqwest::header::HeaderValue::from_static("application/json"),
                );
                map.insert(
                    reqwest::header::HeaderName::from_static("x-remove-me"),
                    reqwest::header::HeaderValue::from_static("should be removed"),
                );
                map
            },
            body: Vec::new().into(),
            context: Arc::new(RwLock::new(RequestContext::default())),
        };

        // Create a header filter
        let mut config = HeaderFilterConfig::default();
        config.add_request_headers.insert("x-custom-header".to_string(), "custom-value".to_string());
        config.remove_request_headers.push("x-remove-me".to_string());

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
        let request = ProxyRequest {
            method: HttpMethod::Get,
            path: "/test".to_string(),
            query: None,
            headers: reqwest::header::HeaderMap::new(),
            body: Vec::new().into(),
            context: Arc::new(RwLock::new(RequestContext::default())),
        };

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
}
