// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

#[cfg(test)]
mod tests {
    use crate::{
        HttpMethod, ProxyRequest, ProxyResponse,
        RequestContext, ResponseContext, ProxyError, FilterType,
        Filter, Router, Route
    };
    use crate::core::ProxyCore;
    use crate::config::{Config, ConfigProvider, ConfigError};
    use async_trait::async_trait;
    use std::sync::Arc;
    use tokio::sync::RwLock;
    use std::time::Duration;
    use serde_json::Value;
    use std::collections::HashMap;

    #[test]
    fn test_http_method_from() {
        assert_eq!(HttpMethod::from(&reqwest::Method::GET), HttpMethod::Get);
        assert_eq!(HttpMethod::from(&reqwest::Method::POST), HttpMethod::Post);
        assert_eq!(HttpMethod::from(&reqwest::Method::PUT), HttpMethod::Put);
        assert_eq!(HttpMethod::from(&reqwest::Method::DELETE), HttpMethod::Delete);
        assert_eq!(HttpMethod::from(&reqwest::Method::HEAD), HttpMethod::Head);
        assert_eq!(HttpMethod::from(&reqwest::Method::OPTIONS), HttpMethod::Options);
        assert_eq!(HttpMethod::from(&reqwest::Method::PATCH), HttpMethod::Patch);
        assert_eq!(HttpMethod::from(&reqwest::Method::TRACE), HttpMethod::Trace);
        assert_eq!(HttpMethod::from(&reqwest::Method::CONNECT), HttpMethod::Connect);
    }

    #[test]
    fn test_http_method_to_string() {
        assert_eq!(HttpMethod::Get.to_string(), "GET");
        assert_eq!(HttpMethod::Post.to_string(), "POST");
        assert_eq!(HttpMethod::Put.to_string(), "PUT");
        assert_eq!(HttpMethod::Delete.to_string(), "DELETE");
        assert_eq!(HttpMethod::Head.to_string(), "HEAD");
        assert_eq!(HttpMethod::Options.to_string(), "OPTIONS");
        assert_eq!(HttpMethod::Patch.to_string(), "PATCH");
        assert_eq!(HttpMethod::Trace.to_string(), "TRACE");
        assert_eq!(HttpMethod::Connect.to_string(), "CONNECT");
    }

    #[test]
    fn test_request_context() {
        let mut context = RequestContext::default();

        // Test attribute manipulation
        context.attributes.insert("key1".to_string(), serde_json::json!("value1"));
        context.attributes.insert("key2".to_string(), serde_json::json!(42));

        assert_eq!(context.attributes.get("key1").unwrap(), &serde_json::json!("value1"));
        assert_eq!(context.attributes.get("key2").unwrap(), &serde_json::json!(42));
    }

    #[test]
    fn test_response_context() {
        let mut context = ResponseContext::default();

        // Test attribute manipulation
        context.attributes.insert("key1".to_string(), serde_json::json!("value1"));
        context.attributes.insert("key2".to_string(), serde_json::json!(42));

        assert_eq!(context.attributes.get("key1").unwrap(), &serde_json::json!("value1"));
        assert_eq!(context.attributes.get("key2").unwrap(), &serde_json::json!(42));
    }

    #[tokio::test]
    async fn test_proxy_request() {
        let context = Arc::new(RwLock::new(RequestContext::default()));
        let request = ProxyRequest {
            method: HttpMethod::Get,
            path: "/test".to_string(),
            query: Some("param=value".to_string()),
            headers: reqwest::header::HeaderMap::new(),
            body: reqwest::Body::from(Vec::new()),
            context: context.clone(),
            custom_target: Option::Some("http://test.co.za".to_string()),
        };

        // Test context manipulation
        {
            let mut ctx = request.context.write().await;
            ctx.attributes.insert("test".to_string(), serde_json::json!("value"));
        }

        let ctx = request.context.read().await;
        assert_eq!(ctx.attributes.get("test").unwrap(), &serde_json::json!("value"));
    }

    #[tokio::test]
    async fn test_proxy_response() {
        let context = Arc::new(RwLock::new(ResponseContext::default()));
        let response = ProxyResponse {
            status: 200,
            headers: reqwest::header::HeaderMap::new(),
            body: reqwest::Body::from(Vec::new()),
            context: context.clone(),
        };

        // Test context manipulation
        {
            let mut ctx = response.context.write().await;
            ctx.attributes.insert("test".to_string(), serde_json::json!("value"));
        }

        let ctx = response.context.read().await;
        assert_eq!(ctx.attributes.get("test").unwrap(), &serde_json::json!("value"));
    }

    // Mock implementations for testing
    #[derive(Debug)]
    struct MockConfigProvider {
        values: HashMap<String, Value>,
    }

    impl MockConfigProvider {
        fn new() -> Self {
            let mut values = HashMap::new();
            values.insert("proxy.timeout".to_string(), Value::Number(30.into()));
            Self { values }
        }

        fn with_value<T: Into<Value>>(mut self, key: &str, value: T) -> Self {
            self.values.insert(key.to_string(), value.into());
            self
        }
    }

    impl ConfigProvider for MockConfigProvider {
        fn has(&self, key: &str) -> bool {
            self.values.contains_key(key)
        }

        fn provider_name(&self) -> &str {
            "mock"
        }

        fn get_raw(&self, key: &str) -> Result<Option<Value>, ConfigError> {
            Ok(self.values.get(key).cloned())
        }
    }

    #[derive(Debug)]
    struct MockRouter {
        routes: Vec<Route>,
        should_fail: bool,
    }

    impl MockRouter {
        fn new() -> Self {
            Self {
                routes: Vec::new(),
                should_fail: false,
            }
        }

        fn with_route(mut self, route: Route) -> Self {
            self.routes.push(route);
            self
        }

        fn with_failure(mut self) -> Self {
            self.should_fail = true;
            self
        }
    }

    #[async_trait]
    impl Router for MockRouter {
        async fn route(&self, _request: &ProxyRequest) -> Result<Route, ProxyError> {
            if self.should_fail {
                return Err(ProxyError::RoutingError("Mock routing failure".to_string()));
            }

            if let Some(route) = self.routes.first() {
                Ok(route.clone())
            } else {
                Err(ProxyError::RoutingError("No routes configured".to_string()))
            }
        }

        async fn get_routes(&self) -> Vec<Route> {
            self.routes.clone()
        }

        async fn add_route(&self, _route: Route) -> Result<(), ProxyError> {
            Ok(())
        }

        async fn remove_route(&self, _route_id: &str) -> Result<(), ProxyError> {
            Ok(())
        }
    }

    #[derive(Debug)]
    struct MockFilter {
        name: String,
        filter_type: FilterType,
        should_fail: bool,
        modify_request: bool,
        modify_response: bool,
    }

    impl MockFilter {
        fn new(name: &str, filter_type: FilterType) -> Self {
            Self {
                name: name.to_string(),
                filter_type,
                should_fail: false,
                modify_request: false,
                modify_response: false,
            }
        }

        fn with_failure(mut self) -> Self {
            self.should_fail = true;
            self
        }

        fn with_request_modification(mut self) -> Self {
            self.modify_request = true;
            self
        }

        fn with_response_modification(mut self) -> Self {
            self.modify_response = true;
            self
        }
    }

    #[async_trait]
    impl Filter for MockFilter {
        fn filter_type(&self) -> FilterType {
            self.filter_type
        }

        fn name(&self) -> &str {
            &self.name
        }

        async fn pre_filter(&self, request: ProxyRequest) -> Result<ProxyRequest, ProxyError> {
            if self.should_fail {
                return Err(ProxyError::FilterError("Mock filter failure".to_string()));
            }

            if self.modify_request {
                let mut ctx = request.context.write().await;
                ctx.attributes.insert("filter_applied".to_string(), Value::String(self.name.clone()));
            }

            Ok(request)
        }

        async fn post_filter(&self, _request: ProxyRequest, response: ProxyResponse) -> Result<ProxyResponse, ProxyError> {
            if self.should_fail {
                return Err(ProxyError::FilterError("Mock filter failure".to_string()));
            }

            if self.modify_response {
                let mut ctx = response.context.write().await;
                ctx.attributes.insert("filter_applied".to_string(), Value::String(self.name.clone()));
            }

            Ok(response)
        }
    }

    // Tests for ProxyError enum
    #[tokio::test]
    async fn test_proxy_error_display() {
        // Create a mock reqwest error by making a request to an invalid URL
        let client = reqwest::Client::new();
        let result = client.get("http://invalid-url-that-does-not-exist.invalid").send().await;
        let client_error = ProxyError::ClientError(result.unwrap_err());
        assert!(client_error.to_string().contains("HTTP client error"));

        let timeout_error = ProxyError::Timeout(Duration::from_secs(30));
        assert!(timeout_error.to_string().contains("request timed out"));

        let routing_error = ProxyError::RoutingError("No route found".to_string());
        assert_eq!(routing_error.to_string(), "routing error: No route found");

        let filter_error = ProxyError::FilterError("Filter failed".to_string());
        assert_eq!(filter_error.to_string(), "filter error: Filter failed");

        let config_error = ProxyError::ConfigError("Invalid config".to_string());
        assert_eq!(config_error.to_string(), "configuration error: Invalid config");

        let security_error = ProxyError::SecurityError("Auth failed".to_string());
        assert_eq!(security_error.to_string(), "security error: Auth failed");

        let other_error = ProxyError::Other("Generic error".to_string());
        assert_eq!(other_error.to_string(), "Generic error");
    }

    #[test]
    fn test_proxy_error_from_io_error() {
        let io_error = std::io::Error::new(std::io::ErrorKind::NotFound, "File not found");
        let proxy_error = ProxyError::from(io_error);
        assert!(proxy_error.to_string().contains("IO error"));
    }

    // Tests for FilterType enum
    #[test]
    fn test_filter_type_equality() {
        assert_eq!(FilterType::Pre, FilterType::Pre);
        assert_eq!(FilterType::Post, FilterType::Post);
        assert_eq!(FilterType::Both, FilterType::Both);

        assert_ne!(FilterType::Pre, FilterType::Post);
        assert_ne!(FilterType::Pre, FilterType::Both);
        assert_ne!(FilterType::Post, FilterType::Both);
    }

    #[test]
    fn test_filter_type_debug() {
        assert_eq!(format!("{:?}", FilterType::Pre), "Pre");
        assert_eq!(format!("{:?}", FilterType::Post), "Post");
        assert_eq!(format!("{:?}", FilterType::Both), "Both");
    }

    // Tests for ProxyRequest cloning
    #[tokio::test]
    async fn test_proxy_request_clone() {
        let original = ProxyRequest {
            method: HttpMethod::Post,
            path: "/api/test".to_string(),
            query: Some("param=value".to_string()),
            headers: {
                let mut headers = reqwest::header::HeaderMap::new();
                headers.insert("content-type", "application/json".parse().unwrap());
                headers
            },
            body: reqwest::Body::from("original body"),
            context: Arc::new(RwLock::new(RequestContext::default())),
            custom_target: Some("http://example.com".to_string()),
        };

        let cloned = original.clone();

        // Verify all fields are cloned correctly
        assert_eq!(cloned.method, original.method);
        assert_eq!(cloned.path, original.path);
        assert_eq!(cloned.query, original.query);
        assert_eq!(cloned.headers, original.headers);
        assert_eq!(cloned.custom_target, original.custom_target);

        // Context should be the same Arc
        assert!(Arc::ptr_eq(&cloned.context, &original.context));

        // Body is cloned but we can't easily test its content since it's streaming
        // The important thing is that the clone operation succeeds
    }

    // Tests for RequestContext
    #[test]
    fn test_request_context_default() {
        let context = RequestContext::default();
        assert!(context.client_ip.is_none());
        assert!(context.start_time.is_none());
        assert!(context.attributes.is_empty());
    }

    #[test]
    fn test_request_context_with_data() {
        let mut context = RequestContext::default();
        context.client_ip = Some("192.168.1.1".to_string());
        context.start_time = Some(std::time::Instant::now());
        context.attributes.insert("user_id".to_string(), Value::String("123".to_string()));

        assert_eq!(context.client_ip.as_ref().unwrap(), "192.168.1.1");
        assert!(context.start_time.is_some());
        assert_eq!(context.attributes.get("user_id").unwrap(), &Value::String("123".to_string()));
    }

    // Tests for ResponseContext
    #[test]
    fn test_response_context_default() {
        let context = ResponseContext::default();
        assert!(context.receive_time.is_none());
        assert!(context.attributes.is_empty());
    }

    #[test]
    fn test_response_context_with_data() {
        let mut context = ResponseContext::default();
        context.receive_time = Some(std::time::Instant::now());
        context.attributes.insert("response_size".to_string(), Value::Number(1024.into()));

        assert!(context.receive_time.is_some());
        assert_eq!(context.attributes.get("response_size").unwrap(), &Value::Number(1024.into()));
    }

    // Tests for Route struct
    #[test]
    fn test_route_creation() {
        let route = Route {
            id: "test-route".to_string(),
            target_base_url: "http://example.com".to_string(),
            path_pattern: "/api/*".to_string(),
            filters: None,
        };

        assert_eq!(route.id, "test-route");
        assert_eq!(route.target_base_url, "http://example.com");
        assert_eq!(route.path_pattern, "/api/*");
        assert!(route.filters.is_none());
    }

    #[test]
    fn test_route_with_filters() {
        let filter = Arc::new(MockFilter::new("test-filter", FilterType::Pre));
        let route = Route {
            id: "test-route".to_string(),
            target_base_url: "http://example.com".to_string(),
            path_pattern: "/api/*".to_string(),
            filters: Some(vec![filter.clone()]),
        };

        assert!(route.filters.is_some());
        let filters = route.filters.unwrap();
        assert_eq!(filters.len(), 1);
        assert_eq!(filters[0].name(), "test-filter");
    }

    // Tests for ProxyCore
    #[tokio::test]
    async fn test_proxy_core_creation() {
        let config_provider = MockConfigProvider::new();
        let config = Arc::new(Config::builder().with_provider(config_provider).build());
        let router = Arc::new(MockRouter::new());

        let proxy_core = ProxyCore::new(config.clone(), router).await;
        assert!(proxy_core.is_ok());

        let core = proxy_core.unwrap();
        assert!(Arc::ptr_eq(&core.config, &config));
    }

    #[tokio::test]
    async fn test_proxy_core_creation_with_custom_timeout() {
        let config_provider = MockConfigProvider::new()
            .with_value("proxy.timeout", 60);
        let config = Arc::new(Config::builder().with_provider(config_provider).build());
        let router = Arc::new(MockRouter::new());

        let proxy_core = ProxyCore::new(config, router).await;
        assert!(proxy_core.is_ok());
    }

    #[tokio::test]
    async fn test_proxy_core_add_global_filter() {
        let config_provider = MockConfigProvider::new();
        let config = Arc::new(Config::builder().with_provider(config_provider).build());
        let router = Arc::new(MockRouter::new());
        let proxy_core = ProxyCore::new(config, router).await.unwrap();

        let filter = Arc::new(MockFilter::new("global-filter", FilterType::Both));
        proxy_core.add_global_filter(filter.clone()).await;

        let filters = proxy_core.global_filters.read().await;
        assert_eq!(filters.len(), 1);
        assert_eq!(filters[0].name(), "global-filter");
    }

    #[tokio::test]
    async fn test_proxy_core_multiple_global_filters() {
        let config_provider = MockConfigProvider::new();
        let config = Arc::new(Config::builder().with_provider(config_provider).build());
        let router = Arc::new(MockRouter::new());
        let proxy_core = ProxyCore::new(config, router).await.unwrap();

        let filter1 = Arc::new(MockFilter::new("filter-1", FilterType::Pre));
        let filter2 = Arc::new(MockFilter::new("filter-2", FilterType::Post));

        proxy_core.add_global_filter(filter1).await;
        proxy_core.add_global_filter(filter2).await;

        let filters = proxy_core.global_filters.read().await;
        assert_eq!(filters.len(), 2);
        assert_eq!(filters[0].name(), "filter-1");
        assert_eq!(filters[1].name(), "filter-2");
    }

    // Helper function to create a test request
    fn create_test_request(method: HttpMethod, path: &str) -> ProxyRequest {
        ProxyRequest {
            method,
            path: path.to_string(),
            query: None,
            headers: reqwest::header::HeaderMap::new(),
            body: reqwest::Body::from(Vec::new()),
            context: Arc::new(RwLock::new(RequestContext::default())),
            custom_target: Some("http://test.example.com".to_string()),
        }
    }

    // Tests for Mock implementations
    #[tokio::test]
    async fn test_mock_router_success() {
        let route = Route {
            id: "test-route".to_string(),
            target_base_url: "http://example.com".to_string(),
            path_pattern: "/api/*".to_string(),
            filters: None,
        };

        let router = MockRouter::new().with_route(route.clone());
        let request = create_test_request(HttpMethod::Get, "/api/users");

        let result = router.route(&request).await;
        assert!(result.is_ok());

        let returned_route = result.unwrap();
        assert_eq!(returned_route.id, route.id);
        assert_eq!(returned_route.target_base_url, route.target_base_url);
    }

    #[tokio::test]
    async fn test_mock_router_failure() {
        let router = MockRouter::new().with_failure();
        let request = create_test_request(HttpMethod::Get, "/api/users");

        let result = router.route(&request).await;
        assert!(result.is_err());

        if let Err(ProxyError::RoutingError(msg)) = result {
            assert_eq!(msg, "Mock routing failure");
        } else {
            panic!("Expected RoutingError");
        }
    }

    #[tokio::test]
    async fn test_mock_router_no_routes() {
        let router = MockRouter::new();
        let request = create_test_request(HttpMethod::Get, "/api/users");

        let result = router.route(&request).await;
        assert!(result.is_err());

        if let Err(ProxyError::RoutingError(msg)) = result {
            assert_eq!(msg, "No routes configured");
        } else {
            panic!("Expected RoutingError");
        }
    }

    // Tests for Filter trait implementations
    #[tokio::test]
    async fn test_mock_filter_pre_filter_success() {
        let filter = MockFilter::new("test-filter", FilterType::Pre);
        let request = create_test_request(HttpMethod::Get, "/test");

        let result = filter.pre_filter(request).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_mock_filter_pre_filter_failure() {
        let filter = MockFilter::new("test-filter", FilterType::Pre).with_failure();
        let request = create_test_request(HttpMethod::Get, "/test");

        let result = filter.pre_filter(request).await;
        assert!(result.is_err());

        if let Err(ProxyError::FilterError(msg)) = result {
            assert_eq!(msg, "Mock filter failure");
        } else {
            panic!("Expected FilterError");
        }
    }

    #[tokio::test]
    async fn test_mock_filter_pre_filter_with_modification() {
        let filter = MockFilter::new("test-filter", FilterType::Pre)
            .with_request_modification();
        let request = create_test_request(HttpMethod::Get, "/test");

        let result = filter.pre_filter(request).await;
        assert!(result.is_ok());

        let modified_request = result.unwrap();
        let ctx = modified_request.context.read().await;
        assert_eq!(
            ctx.attributes.get("filter_applied").unwrap(),
            &Value::String("test-filter".to_string())
        );
    }

    #[tokio::test]
    async fn test_mock_filter_post_filter_success() {
        let filter = MockFilter::new("test-filter", FilterType::Post);
        let request = create_test_request(HttpMethod::Get, "/test");
        let response = ProxyResponse {
            status: 200,
            headers: reqwest::header::HeaderMap::new(),
            body: reqwest::Body::from(Vec::new()),
            context: Arc::new(RwLock::new(ResponseContext::default())),
        };

        let result = filter.post_filter(request, response).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_mock_filter_post_filter_failure() {
        let filter = MockFilter::new("test-filter", FilterType::Post).with_failure();
        let request = create_test_request(HttpMethod::Get, "/test");
        let response = ProxyResponse {
            status: 200,
            headers: reqwest::header::HeaderMap::new(),
            body: reqwest::Body::from(Vec::new()),
            context: Arc::new(RwLock::new(ResponseContext::default())),
        };

        let result = filter.post_filter(request, response).await;
        assert!(result.is_err());

        if let Err(ProxyError::FilterError(msg)) = result {
            assert_eq!(msg, "Mock filter failure");
        } else {
            panic!("Expected FilterError");
        }
    }

    #[tokio::test]
    async fn test_mock_filter_post_filter_with_modification() {
        let filter = MockFilter::new("test-filter", FilterType::Post)
            .with_response_modification();
        let request = create_test_request(HttpMethod::Get, "/test");
        let response = ProxyResponse {
            status: 200,
            headers: reqwest::header::HeaderMap::new(),
            body: reqwest::Body::from(Vec::new()),
            context: Arc::new(RwLock::new(ResponseContext::default())),
        };

        let result = filter.post_filter(request, response).await;
        assert!(result.is_ok());

        let modified_response = result.unwrap();
        let ctx = modified_response.context.read().await;
        assert_eq!(
            ctx.attributes.get("filter_applied").unwrap(),
            &Value::String("test-filter".to_string())
        );
    }

    #[test]
    fn test_mock_filter_properties() {
        let filter = MockFilter::new("test-filter", FilterType::Both);
        assert_eq!(filter.name(), "test-filter");
        assert_eq!(filter.filter_type(), FilterType::Both);
    }

    // Tests for Router trait implementations
    #[tokio::test]
    async fn test_mock_router_get_routes() {
        let route1 = Route {
            id: "route-1".to_string(),
            target_base_url: "http://example1.com".to_string(),
            path_pattern: "/api/*".to_string(),
            filters: None,
        };
        let route2 = Route {
            id: "route-2".to_string(),
            target_base_url: "http://example2.com".to_string(),
            path_pattern: "/v2/*".to_string(),
            filters: None,
        };

        let router = MockRouter::new()
            .with_route(route1.clone())
            .with_route(route2.clone());

        let routes = router.get_routes().await;
        assert_eq!(routes.len(), 2);
        assert_eq!(routes[0].id, "route-1");
        assert_eq!(routes[1].id, "route-2");
    }

    #[tokio::test]
    async fn test_mock_router_add_remove_route() {
        let router = MockRouter::new();
        let route = Route {
            id: "test-route".to_string(),
            target_base_url: "http://example.com".to_string(),
            path_pattern: "/test/*".to_string(),
            filters: None,
        };

        // Test add_route
        let result = router.add_route(route).await;
        assert!(result.is_ok());

        // Test remove_route
        let result = router.remove_route("test-route").await;
        assert!(result.is_ok());
    }
}
