// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

#[cfg(test)]
mod tests {
    use crate::{
        HttpMethod, ProxyRequest, ProxyResponse, ProxyError,
        SecurityProvider, SecurityChain, SecurityStage
    };
    use crate::core::RequestContext;
    use async_trait::async_trait;
    use reqwest::Body;
    use std::sync::Arc;
    use tokio::sync::RwLock;

    // Helper function to create a test request
    fn create_test_request(method: HttpMethod, path: &str, headers: Vec<(&'static str, &'static str)>, target: &str) -> ProxyRequest {
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
            body: Body::from(Vec::new()),
            context: Arc::new(RwLock::new(RequestContext::default())),
            target: target.to_string(),
        }
    }

    #[tokio::test]
    async fn test_security_chain_bypass_routes() {
        // Create a security chain with a mock provider
        let mut chain = SecurityChain::new(vec!["/health".to_string(), "/public/".to_string()]);

        // Add a mock provider
        let mock_provider = MockSecurityProvider::new();

        chain.add(Arc::new(mock_provider));

        // Test bypass routes
        let request = create_test_request(HttpMethod::Get, "/health", vec![], "http://test.co.za");
        let result = chain.apply_pre(request).await;
        assert!(result.is_ok());

        let request = create_test_request(HttpMethod::Post, "/health", vec![], "http://test.co.za");
        let result = chain.apply_pre(request).await;
        assert!(result.is_ok());

        let request = create_test_request(HttpMethod::Get, "/public/docs", vec![], "http://test.co.za");
        let result = chain.apply_pre(request).await;
        assert!(result.is_ok());

        // Test non-bypass route
        let request = create_test_request(HttpMethod::Get, "/api/users", vec![], "http://test.co.za");
        let result = chain.apply_pre(request).await;
        assert!(result.is_err());
    }

    // Mock implementations for testing
    #[derive(Debug)]
    struct MockSecurityProvider {}

    impl MockSecurityProvider {
        fn new() -> Self {
            Self {}
        }
    }

    #[async_trait]
    impl SecurityProvider for MockSecurityProvider {
        fn stage(&self) -> SecurityStage {
            SecurityStage::Both
        }

        fn name(&self) -> &str {
            "mock-provider"
        }

        async fn pre(&self, request: ProxyRequest) -> Result<ProxyRequest, ProxyError> {
            // This mock always fails authentication unless bypassed
            Err(ProxyError::SecurityError("Mock authentication failure".to_string()))
        }
    }
}
