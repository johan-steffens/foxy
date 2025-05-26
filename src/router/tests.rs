// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

#[cfg(test)]
mod tests {
    use crate::{
        HttpMethod, ProxyRequest,
        PathPredicate, MethodPredicate, HeaderPredicate, QueryPredicate
    };
    use crate::router::predicates::{
        PathPredicateConfig, MethodPredicateConfig, HeaderPredicateConfig, QueryPredicateConfig
    };
    use crate::router::Predicate;
    use crate::core::RequestContext;
    use reqwest::Body;
    use std::sync::Arc;
    use tokio::sync::RwLock;
    use std::collections::HashMap;

    // Helper function to create a test request
    fn create_test_request(method: HttpMethod, path: &str, query: Option<&str>, headers: Vec<(&'static str, &'static str)>, target: &str) -> ProxyRequest {
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
            target: target.to_string(),
        }
    }

    #[tokio::test]
    async fn test_path_predicate() {
        let config = PathPredicateConfig {
            pattern: "/api/*".to_string(),
        };
        let predicate = PathPredicate::new(config).unwrap();

        // Test matching paths
        let request = create_test_request(HttpMethod::Get, "/api/users", None, vec![], "http://test.co.za");
        assert!(predicate.matches(&request).await);

        let request = create_test_request(HttpMethod::Get, "/api/products", None, vec![], "http://test.co.za");
        assert!(predicate.matches(&request).await);

        // Test non-matching paths
        let request = create_test_request(HttpMethod::Get, "/users", None, vec![], "http://test.co.za");
        assert!(!predicate.matches(&request).await);

        let request = create_test_request(HttpMethod::Get, "/api", None, vec![], "http://test.co.za");
        assert!(!predicate.matches(&request).await);
    }

    #[tokio::test]
    async fn test_method_predicate() {
        let config = MethodPredicateConfig {
            methods: vec![HttpMethod::Get, HttpMethod::Post],
        };
        let predicate = MethodPredicate::new(config);

        // Test matching methods
        let request = create_test_request(HttpMethod::Get, "/api", None, vec![], "http://test.co.za");
        assert!(predicate.matches(&request).await);

        let request = create_test_request(HttpMethod::Post, "/api", None, vec![], "http://test.co.za");
        assert!(predicate.matches(&request).await);

        // Test non-matching methods
        let request = create_test_request(HttpMethod::Put, "/api", None, vec![], "http://test.co.za");
        assert!(!predicate.matches(&request).await);

        let request = create_test_request(HttpMethod::Delete, "/api", None, vec![], "http://test.co.za");
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

        let request = create_test_request(HttpMethod::Get, "/api", None, vec![], "http://test.co.za");
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
        let request = create_test_request(HttpMethod::Get, "/api", Some("version=v1"), vec![], "http://test.co.za");
        assert!(predicate.matches(&request).await);

        // Test non-matching query parameters
        let request = create_test_request(HttpMethod::Get, "/api", Some("version=v2"), vec![], "http://test.co.za");
        assert!(!predicate.matches(&request).await);

        let request = create_test_request(HttpMethod::Get, "/api", Some("other=value"), vec![], "http://test.co.za");
        assert!(!predicate.matches(&request).await);

        let request = create_test_request(HttpMethod::Get, "/api", None, vec![],"http://test.co.za");
        assert!(!predicate.matches(&request).await);
    }
}
