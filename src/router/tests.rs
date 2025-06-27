// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

#[cfg(test)]
mod router_tests {
    use crate::core::RequestContext;
    use crate::router::Predicate;
    use crate::router::predicates::{
        HeaderPredicateConfig, MethodPredicateConfig, PathPredicateConfig, QueryPredicateConfig,
    };
    use crate::{
        HeaderPredicate, HttpMethod, MethodPredicate, PathPredicate, ProxyRequest, QueryPredicate,
    };
    use reqwest::Body;
    use std::collections::HashMap;
    use std::sync::Arc;
    use tokio::sync::RwLock;

    // Helper function to create a test request
    fn create_test_request(
        method: HttpMethod,
        path: &str,
        query: Option<&str>,
        headers: Vec<(&'static str, &'static str)>,
        target: &str,
    ) -> ProxyRequest {
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
            query: query.map(|q| q.to_string()),
            headers: header_map,
            body: Body::from(Vec::new()),
            context: Arc::new(RwLock::new(RequestContext::default())),
            custom_target: Some(target.to_string()),
        }
    }

    #[tokio::test]
    async fn test_path_predicate() {
        let config = PathPredicateConfig {
            pattern: "/api/*".to_string(),
        };
        let predicate = PathPredicate::new(config).unwrap();

        // Test matching paths
        let request = create_test_request(
            HttpMethod::Get,
            "/api/users",
            None,
            vec![],
            "http://test.co.za",
        );
        assert!(predicate.matches(&request).await);

        let request = create_test_request(
            HttpMethod::Get,
            "/api/products",
            None,
            vec![],
            "http://test.co.za",
        );
        assert!(predicate.matches(&request).await);

        // Test non-matching paths
        let request =
            create_test_request(HttpMethod::Get, "/users", None, vec![], "http://test.co.za");
        assert!(!predicate.matches(&request).await);

        let request =
            create_test_request(HttpMethod::Get, "/api", None, vec![], "http://test.co.za");
        assert!(!predicate.matches(&request).await);
    }

    #[tokio::test]
    async fn test_method_predicate() {
        let config = MethodPredicateConfig {
            methods: vec![HttpMethod::Get, HttpMethod::Post],
        };
        let predicate = MethodPredicate::new(config);

        // Test matching methods
        let request =
            create_test_request(HttpMethod::Get, "/api", None, vec![], "http://test.co.za");
        assert!(predicate.matches(&request).await);

        let request =
            create_test_request(HttpMethod::Post, "/api", None, vec![], "http://test.co.za");
        assert!(predicate.matches(&request).await);

        // Test non-matching methods
        let request =
            create_test_request(HttpMethod::Put, "/api", None, vec![], "http://test.co.za");
        assert!(!predicate.matches(&request).await);

        let request = create_test_request(
            HttpMethod::Delete,
            "/api",
            None,
            vec![],
            "http://test.co.za",
        );
        assert!(!predicate.matches(&request).await);
    }

    #[tokio::test]
    async fn test_header_predicate() {
        let mut headers = HashMap::new();
        headers.insert("content-type".to_string(), "application/json".to_string());

        let config = HeaderPredicateConfig {
            headers,
            exact_match: true,
        };
        let predicate = HeaderPredicate::new(config);

        // Test matching headers
        let request = create_test_request(
            HttpMethod::Get,
            "/api",
            None,
            vec![("content-type", "application/json")],
            "http://test.co.za",
        );
        assert!(predicate.matches(&request).await);

        // Test non-matching headers
        let request = create_test_request(
            HttpMethod::Get,
            "/api",
            None,
            vec![("content-type", "text/plain")],
            "http://test.co.za",
        );
        assert!(!predicate.matches(&request).await);

        let request =
            create_test_request(HttpMethod::Get, "/api", None, vec![], "http://test.co.za");
        assert!(!predicate.matches(&request).await);
    }

    #[tokio::test]
    async fn test_query_predicate() {
        let mut params = HashMap::new();
        params.insert("version".to_string(), "v1".to_string());

        let config = QueryPredicateConfig {
            params,
            exact_match: true,
        };
        let predicate = QueryPredicate::new(config);

        // Test matching query parameters
        let request = create_test_request(
            HttpMethod::Get,
            "/api",
            Some("version=v1"),
            vec![],
            "http://test.co.za",
        );
        assert!(predicate.matches(&request).await);

        // Test non-matching query parameters
        let request = create_test_request(
            HttpMethod::Get,
            "/api",
            Some("version=v2"),
            vec![],
            "http://test.co.za",
        );
        assert!(!predicate.matches(&request).await);

        let request = create_test_request(
            HttpMethod::Get,
            "/api",
            Some("other=value"),
            vec![],
            "http://test.co.za",
        );
        assert!(!predicate.matches(&request).await);

        let request =
            create_test_request(HttpMethod::Get, "/api", None, vec![], "http://test.co.za");
        assert!(!predicate.matches(&request).await);
    }

    // Tests for PredicateRouter
    #[tokio::test]
    async fn test_predicate_router_new() {
        use crate::config::{Config, ConfigProvider};
        use crate::router::PredicateRouter;
        use std::sync::Arc;

        // Create a mock config provider
        #[derive(Debug)]
        struct MockConfigProvider;

        impl ConfigProvider for MockConfigProvider {
            fn has(&self, _key: &str) -> bool {
                false
            }

            fn provider_name(&self) -> &str {
                "mock"
            }

            fn get_raw(
                &self,
                _key: &str,
            ) -> Result<Option<serde_json::Value>, crate::config::ConfigError> {
                Ok(None)
            }
        }

        let config = Arc::new(Config::builder().with_provider(MockConfigProvider).build());
        let router = PredicateRouter::new(config).await;
        assert!(router.is_ok());
    }

    #[tokio::test]
    async fn test_predicate_router_add_route() {
        use crate::config::{Config, ConfigProvider};
        use crate::core::{Route, Router};
        use crate::router::PredicateRouter;
        use std::sync::Arc;

        #[derive(Debug)]
        struct MockConfigProvider;

        impl ConfigProvider for MockConfigProvider {
            fn has(&self, _key: &str) -> bool {
                false
            }

            fn provider_name(&self) -> &str {
                "mock"
            }

            fn get_raw(
                &self,
                _key: &str,
            ) -> Result<Option<serde_json::Value>, crate::config::ConfigError> {
                Ok(None)
            }
        }

        let config = Arc::new(Config::builder().with_provider(MockConfigProvider).build());
        let router = PredicateRouter::new(config).await.unwrap();

        let route = Route {
            id: "test-route".to_string(),
            target_base_url: "http://example.com".to_string(),
            path_pattern: "/api/*".to_string(),
            filters: None,
        };

        let result = router.add_route(route.clone()).await;
        assert!(result.is_ok());

        let routes = router.get_routes().await;
        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].id, "test-route");
    }

    #[tokio::test]
    async fn test_predicate_router_remove_route() {
        use crate::config::{Config, ConfigProvider};
        use crate::core::{Route, Router};
        use crate::router::PredicateRouter;
        use std::sync::Arc;

        #[derive(Debug)]
        struct MockConfigProvider;

        impl ConfigProvider for MockConfigProvider {
            fn has(&self, _key: &str) -> bool {
                false
            }

            fn provider_name(&self) -> &str {
                "mock"
            }

            fn get_raw(
                &self,
                _key: &str,
            ) -> Result<Option<serde_json::Value>, crate::config::ConfigError> {
                Ok(None)
            }
        }

        let config = Arc::new(Config::builder().with_provider(MockConfigProvider).build());
        let router = PredicateRouter::new(config).await.unwrap();

        let route = Route {
            id: "test-route".to_string(),
            target_base_url: "http://example.com".to_string(),
            path_pattern: "/api/*".to_string(),
            filters: None,
        };

        // Add route
        router.add_route(route).await.unwrap();
        assert_eq!(router.get_routes().await.len(), 1);

        // Remove route
        let result = router.remove_route("test-route").await;
        assert!(result.is_ok());
        assert_eq!(router.get_routes().await.len(), 0);

        // Try to remove non-existent route
        let result = router.remove_route("non-existent").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_predicate_router_route_no_match() {
        use crate::config::{Config, ConfigProvider};
        use crate::core::Router;
        use crate::router::PredicateRouter;
        use std::sync::Arc;

        #[derive(Debug)]
        struct MockConfigProvider;

        impl ConfigProvider for MockConfigProvider {
            fn has(&self, _key: &str) -> bool {
                false
            }

            fn provider_name(&self) -> &str {
                "mock"
            }

            fn get_raw(
                &self,
                _key: &str,
            ) -> Result<Option<serde_json::Value>, crate::config::ConfigError> {
                Ok(None)
            }
        }

        let config = Arc::new(Config::builder().with_provider(MockConfigProvider).build());
        let router = PredicateRouter::new(config).await.unwrap();

        let request = create_test_request(
            HttpMethod::Get,
            "/api/users",
            None,
            vec![],
            "http://test.co.za",
        );
        let result = router.route(&request).await;
        assert!(result.is_err());
    }

    // Tests for PredicateFactory
    #[tokio::test]
    async fn test_predicate_factory_create_path_predicate() {
        use crate::router::PredicateFactory;
        use serde_json::json;

        let config = json!({
            "pattern": "/api/*"
        });

        let predicate = PredicateFactory::create_predicate("path", config).unwrap();
        assert_eq!(predicate.predicate_type(), "path");

        let request = create_test_request(
            HttpMethod::Get,
            "/api/users",
            None,
            vec![],
            "http://test.co.za",
        );
        assert!(predicate.matches(&request).await);
    }

    #[tokio::test]
    async fn test_predicate_factory_create_method_predicate() {
        use crate::router::PredicateFactory;
        use serde_json::json;

        let config = json!({
            "methods": ["GET", "POST"]
        });

        let predicate = PredicateFactory::create_predicate("method", config).unwrap();
        assert_eq!(predicate.predicate_type(), "method");

        let request =
            create_test_request(HttpMethod::Get, "/api", None, vec![], "http://test.co.za");
        assert!(predicate.matches(&request).await);
    }

    #[tokio::test]
    async fn test_predicate_factory_create_header_predicate() {
        use crate::router::PredicateFactory;
        use serde_json::json;

        let config = json!({
            "headers": {
                "content-type": "application/json"
            },
            "exact_match": true
        });

        let predicate = PredicateFactory::create_predicate("header", config).unwrap();
        assert_eq!(predicate.predicate_type(), "header");

        let request = create_test_request(
            HttpMethod::Get,
            "/api",
            None,
            vec![("content-type", "application/json")],
            "http://test.co.za",
        );
        assert!(predicate.matches(&request).await);
    }

    #[tokio::test]
    async fn test_predicate_factory_create_query_predicate() {
        use crate::router::PredicateFactory;
        use serde_json::json;

        let config = json!({
            "params": {
                "version": "v1"
            },
            "exact_match": true
        });

        let predicate = PredicateFactory::create_predicate("query", config).unwrap();
        assert_eq!(predicate.predicate_type(), "query");

        let request = create_test_request(
            HttpMethod::Get,
            "/api",
            Some("version=v1"),
            vec![],
            "http://test.co.za",
        );
        assert!(predicate.matches(&request).await);
    }

    #[tokio::test]
    async fn test_predicate_factory_unknown_predicate() {
        use crate::router::PredicateFactory;
        use serde_json::json;

        let config = json!({});
        let result = PredicateFactory::create_predicate("unknown", config);
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_predicate_factory_invalid_config() {
        use crate::router::PredicateFactory;
        use serde_json::json;

        let config = json!({
            "invalid_field": "value"
        });

        let result = PredicateFactory::create_predicate("path", config);
        assert!(result.is_err());
    }

    // Tests for predicate edge cases
    #[tokio::test]
    async fn test_path_predicate_invalid_regex() {
        // Since the pattern_to_regex method escapes most special characters,
        // it's difficult to create an invalid regex. Let's test a pattern that
        // would create a regex with too many nested groups or other edge cases.
        // For now, let's just test that the method handles edge cases gracefully.
        let config = PathPredicateConfig {
            pattern: "/api/*".to_string(), // This should work fine
        };
        let result = PathPredicate::new(config);
        assert!(result.is_ok());

        // Test empty pattern
        let config = PathPredicateConfig {
            pattern: "".to_string(),
        };
        let result = PathPredicate::new(config);
        assert!(result.is_ok()); // Empty pattern should be valid
    }

    #[tokio::test]
    async fn test_path_predicate_complex_patterns() {
        // Test exact path
        let config = PathPredicateConfig {
            pattern: "/api/users".to_string(),
        };
        let predicate = PathPredicate::new(config).unwrap();

        let request = create_test_request(
            HttpMethod::Get,
            "/api/users",
            None,
            vec![],
            "http://test.co.za",
        );
        assert!(predicate.matches(&request).await);

        let request = create_test_request(
            HttpMethod::Get,
            "/api/users/123",
            None,
            vec![],
            "http://test.co.za",
        );
        assert!(!predicate.matches(&request).await);

        // Test wildcard pattern
        let config = PathPredicateConfig {
            pattern: "/api/*/details".to_string(),
        };
        let predicate = PathPredicate::new(config).unwrap();

        let request = create_test_request(
            HttpMethod::Get,
            "/api/users/details",
            None,
            vec![],
            "http://test.co.za",
        );
        assert!(predicate.matches(&request).await);

        let request = create_test_request(
            HttpMethod::Get,
            "/api/products/details",
            None,
            vec![],
            "http://test.co.za",
        );
        assert!(predicate.matches(&request).await);
    }

    #[tokio::test]
    async fn test_header_predicate_contains_match() {
        let mut headers = HashMap::new();
        headers.insert("user-agent".to_string(), "Mozilla".to_string());

        let config = HeaderPredicateConfig {
            headers,
            exact_match: false, // Contains match
        };
        let predicate = HeaderPredicate::new(config);

        // Test contains match
        let request = create_test_request(
            HttpMethod::Get,
            "/api",
            None,
            vec![("user-agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)")],
            "http://test.co.za",
        );
        assert!(predicate.matches(&request).await);

        // Test non-matching header
        let request = create_test_request(
            HttpMethod::Get,
            "/api",
            None,
            vec![("user-agent", "Chrome/91.0")],
            "http://test.co.za",
        );
        assert!(!predicate.matches(&request).await);
    }

    #[tokio::test]
    async fn test_header_predicate_multiple_headers() {
        let mut headers = HashMap::new();
        headers.insert("content-type".to_string(), "application/json".to_string());
        headers.insert("authorization".to_string(), "Bearer".to_string());

        let config = HeaderPredicateConfig {
            headers,
            exact_match: false,
        };
        let predicate = HeaderPredicate::new(config);

        // Test all headers match
        let request = create_test_request(
            HttpMethod::Get,
            "/api",
            None,
            vec![
                ("content-type", "application/json"),
                ("authorization", "Bearer token123"),
            ],
            "http://test.co.za",
        );
        assert!(predicate.matches(&request).await);

        // Test missing one header
        let request = create_test_request(
            HttpMethod::Get,
            "/api",
            None,
            vec![("content-type", "application/json")],
            "http://test.co.za",
        );
        assert!(!predicate.matches(&request).await);
    }

    #[tokio::test]
    async fn test_query_predicate_contains_match() {
        let mut params = HashMap::new();
        params.insert("search".to_string(), "user".to_string());

        let config = QueryPredicateConfig {
            params,
            exact_match: false, // Contains match
        };
        let predicate = QueryPredicate::new(config);

        // Test contains match
        let request = create_test_request(
            HttpMethod::Get,
            "/api",
            Some("search=username"),
            vec![],
            "http://test.co.za",
        );
        assert!(predicate.matches(&request).await);

        // Test non-matching parameter
        let request = create_test_request(
            HttpMethod::Get,
            "/api",
            Some("search=product"),
            vec![],
            "http://test.co.za",
        );
        assert!(!predicate.matches(&request).await);
    }

    #[tokio::test]
    async fn test_query_predicate_multiple_params() {
        let mut params = HashMap::new();
        params.insert("version".to_string(), "v1".to_string());
        params.insert("format".to_string(), "json".to_string());

        let config = QueryPredicateConfig {
            params,
            exact_match: true,
        };
        let predicate = QueryPredicate::new(config);

        // Test all parameters match
        let request = create_test_request(
            HttpMethod::Get,
            "/api",
            Some("version=v1&format=json"),
            vec![],
            "http://test.co.za",
        );
        assert!(predicate.matches(&request).await);

        // Test missing one parameter
        let request = create_test_request(
            HttpMethod::Get,
            "/api",
            Some("version=v1"),
            vec![],
            "http://test.co.za",
        );
        assert!(!predicate.matches(&request).await);

        // Test wrong parameter value
        let request = create_test_request(
            HttpMethod::Get,
            "/api",
            Some("version=v2&format=json"),
            vec![],
            "http://test.co.za",
        );
        assert!(!predicate.matches(&request).await);
    }

    #[tokio::test]
    async fn test_query_predicate_empty_params() {
        let config = QueryPredicateConfig {
            params: HashMap::new(),
            exact_match: true,
        };
        let predicate = QueryPredicate::new(config);

        // Empty params should always match
        let request =
            create_test_request(HttpMethod::Get, "/api", None, vec![], "http://test.co.za");
        assert!(predicate.matches(&request).await);

        let request = create_test_request(
            HttpMethod::Get,
            "/api",
            Some("any=value"),
            vec![],
            "http://test.co.za",
        );
        assert!(predicate.matches(&request).await);
    }

    // Note: parse_query_params is a private method, so we test it indirectly through the predicate matching

    // Tests for predicate registration
    #[tokio::test]
    async fn test_register_predicate() {
        use crate::core::ProxyRequest;
        use crate::router::{PredicateFactory, register_predicate};
        use serde_json::json;
        use std::sync::Arc;

        // Define a custom predicate
        #[derive(Debug)]
        struct CustomPredicate;

        #[async_trait::async_trait]
        impl crate::router::Predicate for CustomPredicate {
            async fn matches(&self, _request: &ProxyRequest) -> bool {
                true // Always matches for testing
            }

            fn predicate_type(&self) -> &str {
                "custom"
            }
        }

        // Register the custom predicate
        register_predicate("custom_test", |_config| Ok(Arc::new(CustomPredicate)));

        // Create the predicate using the factory
        let config = json!({});
        let predicate = PredicateFactory::create_predicate("custom_test", config).unwrap();
        assert_eq!(predicate.predicate_type(), "custom");

        let request =
            create_test_request(HttpMethod::Get, "/test", None, vec![], "http://test.co.za");
        assert!(predicate.matches(&request).await);
    }

    // Note: pattern_to_regex is a private method, so we test it indirectly through the predicate matching

    // Tests for method predicate edge cases
    #[tokio::test]
    async fn test_method_predicate_empty_methods() {
        let config = MethodPredicateConfig { methods: vec![] };
        let predicate = MethodPredicate::new(config);

        // Empty methods should not match anything
        let request =
            create_test_request(HttpMethod::Get, "/api", None, vec![], "http://test.co.za");
        assert!(!predicate.matches(&request).await);
    }

    #[tokio::test]
    async fn test_method_predicate_all_methods() {
        let config = MethodPredicateConfig {
            methods: vec![
                HttpMethod::Get,
                HttpMethod::Post,
                HttpMethod::Put,
                HttpMethod::Delete,
                HttpMethod::Patch,
                HttpMethod::Head,
                HttpMethod::Options,
            ],
        };
        let predicate = MethodPredicate::new(config);

        // Test all HTTP methods
        for method in &[
            HttpMethod::Get,
            HttpMethod::Post,
            HttpMethod::Put,
            HttpMethod::Delete,
            HttpMethod::Patch,
            HttpMethod::Head,
            HttpMethod::Options,
        ] {
            let request =
                create_test_request(*method, "/api", None, vec![], "http://test.co.za");
            assert!(predicate.matches(&request).await);
        }
    }

    // Tests for header predicate edge cases
    #[tokio::test]
    async fn test_header_predicate_invalid_utf8() {
        let mut headers = HashMap::new();
        headers.insert("custom-header".to_string(), "test".to_string());

        let config = HeaderPredicateConfig {
            headers,
            exact_match: true,
        };
        let predicate = HeaderPredicate::new(config);

        // Create a request with invalid UTF-8 header value
        let mut header_map = reqwest::header::HeaderMap::new();
        header_map.insert(
            "custom-header",
            reqwest::header::HeaderValue::from_bytes(&[0xFF, 0xFE]).unwrap(),
        );

        let request = ProxyRequest {
            method: HttpMethod::Get,
            path: "/api".to_string(),
            query: None,
            headers: header_map,
            body: reqwest::Body::from(Vec::new()),
            context: Arc::new(RwLock::new(RequestContext::default())),
            custom_target: Some("http://test.co.za".to_string()),
        };

        assert!(!predicate.matches(&request).await);
    }
}
