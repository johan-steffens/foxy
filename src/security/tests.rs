// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

#[cfg(test)]
mod tests {
    use crate::{
        HttpMethod, ProxyRequest, ProxyError,
        SecurityProvider, SecurityChain, SecurityStage, 
    };
    use crate::core::RequestContext;
    use async_trait::async_trait;
    use reqwest::Body;
    use std::sync::Arc;
    use tokio::sync::RwLock;

    // Helper function to create a test request
    fn create_test_request(method: HttpMethod, path: &str, headers: Vec<(&'static str, &'static str)>) -> ProxyRequest {
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
            custom_target: Some("http://test.co.za".to_string()),
        }
    }

    // Mock implementations for testing
    #[derive(Debug)]
    struct MockSecurityProvider {
        bypassed: bool,
    }

    impl MockSecurityProvider {
        fn new(bypassed: bool) -> Self {
            Self { bypassed }
        }
    }

    #[async_trait]
    impl SecurityProvider for MockSecurityProvider {
        fn stage(&self) -> SecurityStage {
            SecurityStage::Pre
        }

        fn name(&self) -> &str {
            "mock-provider"
        }

        async fn pre(&self, request: ProxyRequest) -> Result<ProxyRequest, ProxyError> {
            // This mock always fails authentication unless it's configured to be bypassed
            if self.bypassed {
                Ok(request)
            } else {
                Err(ProxyError::SecurityError("Mock authentication failure".to_string()))
            }
        }
    }

    #[tokio::test]
    async fn test_security_chain_with_providers() {
        // Create a security chain
        let mut chain = SecurityChain::new();

        // Add a provider that will fail the request
        let failing_provider = MockSecurityProvider::new(false);
        chain.add(Arc::new(failing_provider));

        // Test that the chain fails
        let request = create_test_request(HttpMethod::Get, "/api/users", vec![]);
        let result = chain.apply_pre(request).await;
        assert!(result.is_err());
        if let Err(ProxyError::SecurityError(msg)) = result {
            assert!(msg.contains("Mock authentication failure"));
        } else {
            panic!("Expected a SecurityError");
        }
    }

    #[tokio::test]
    async fn test_security_chain_with_oidc_bypass() {
        // This test simulates how a provider like OidcProvider would handle its own bypass logic.
        // We create a mock OIDC provider that internally checks for a bypass condition.

        #[derive(Debug)]
        struct MockOidcProviderWithBypass;

        #[async_trait]
        impl SecurityProvider for MockOidcProviderWithBypass {
            fn stage(&self) -> SecurityStage { SecurityStage::Pre }
            fn name(&self) -> &str { "mock-oidc-with-bypass" }

            async fn pre(&self, request: ProxyRequest) -> Result<ProxyRequest, ProxyError> {
                // Internal bypass logic
                if request.path == "/health" {
                    return Ok(request); // Bypass
                }
                // Fail otherwise
                Err(ProxyError::SecurityError("OIDC validation failed".to_string()))
            }
        }

        let mut chain = SecurityChain::new();
        chain.add(Arc::new(MockOidcProviderWithBypass));

        // Test bypassed route
        let request_bypassed = create_test_request(HttpMethod::Get, "/health", vec![]);
        assert!(chain.apply_pre(request_bypassed).await.is_ok());

        // Test non-bypassed route
        let request_blocked = create_test_request(HttpMethod::Get, "/api/data", vec![]);
        assert!(chain.apply_pre(request_blocked).await.is_err());
    }

    #[tokio::test]
    async fn test_basic_auth_provider_success() {
        use crate::security::basic::{BasicAuthConfig, BasicAuthProvider, RouteRuleConfig};

        let config = BasicAuthConfig {
            credentials: vec!["user1:pass1".to_string(), "user2:pass2".to_string()],
            bypass: vec![],
        };
        let provider = BasicAuthProvider::new(config).unwrap();
        let chain = SecurityChain::from_configs(vec![
            crate::security::ProviderConfig {
                type_: "basic".to_string(),
                config: serde_json::to_value(BasicAuthConfig {
                    credentials: vec!["user1:pass1".to_string()],
                    bypass: vec![],
                }).unwrap(),
            }
        ]).await.unwrap();

        let request = create_test_request(
            HttpMethod::Get,
            "/protected",
            vec![("authorization", "Basic dXNlcjE6cGFzczE=")], // user1:pass1 base64 encoded
        );
        assert!(chain.apply_pre(request).await.is_ok());
    }

    #[tokio::test]
    async fn test_basic_auth_provider_failure_invalid_credentials() {
        use crate::security::basic::{BasicAuthConfig, BasicAuthProvider, RouteRuleConfig};

        let config = BasicAuthConfig {
            credentials: vec!["user1:pass1".to_string()],
            bypass: vec![],
        };
        let provider = BasicAuthProvider::new(config).unwrap();
        let chain = SecurityChain::from_configs(vec![
            crate::security::ProviderConfig {
                type_: "basic".to_string(),
                config: serde_json::to_value(BasicAuthConfig {
                    credentials: vec!["user1:pass1".to_string()],
                    bypass: vec![],
                }).unwrap(),
            }
        ]).await.unwrap();

        let request = create_test_request(
            HttpMethod::Get,
            "/protected",
            vec![("authorization", "Basic dXNlcjE6d3JvbmdwYXNz")], // user1:wrongpass base64 encoded
        );
        assert!(chain.apply_pre(request).await.is_err());
    }

    #[tokio::test]
    async fn test_basic_auth_provider_bypass() {
        use crate::security::basic::{BasicAuthConfig, BasicAuthProvider, RouteRuleConfig};

        let config = BasicAuthConfig {
            credentials: vec!["user1:pass1".to_string()],
            bypass: vec![
                RouteRuleConfig {
                    methods: vec!["GET".to_string()],
                    path: "/public/*".to_string(),
                },
            ],
        };
        let provider = BasicAuthProvider::new(config).unwrap();
        let chain = SecurityChain::from_configs(vec![
            crate::security::ProviderConfig {
                type_: "basic".to_string(),
                config: serde_json::to_value(BasicAuthConfig {
                    credentials: vec!["user1:pass1".to_string()],
                    bypass: vec![
                        RouteRuleConfig {
                            methods: vec!["GET".to_string()],
                            path: "/public/*".to_string(),
                        },
                    ],
                }).unwrap(),
            }
        ]).await.unwrap();

        // Test bypassed route
        let request_bypassed = create_test_request(HttpMethod::Get, "/public/data", vec![]);
        assert!(chain.apply_pre(request_bypassed).await.is_ok());

        // Test non-bypassed route (missing auth header)
        let request_blocked_no_auth = create_test_request(HttpMethod::Get, "/protected", vec![]);
        assert!(chain.apply_pre(request_blocked_no_auth).await.is_err());

        // Test non-bypassed route (wrong auth header)
        let request_blocked_wrong_auth = create_test_request(
            HttpMethod::Get,
            "/protected",
            vec![("authorization", "Basic dXNlcjE6d3JvbmdwYXNz")],
        );
        assert!(chain.apply_pre(request_blocked_wrong_auth).await.is_err());
    }
}
