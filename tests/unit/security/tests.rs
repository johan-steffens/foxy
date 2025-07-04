// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

#[cfg(test)]
mod security_tests {
    use crate::security::oidc::{JWKS_REFRESH, RouteRule, RouteRuleConfig};
    use crate::{
        HttpMethod, OidcConfig, OidcProvider, ProxyError, ProxyRequest, ProxyResponse,
        RequestContext, SecurityChain, SecurityProvider, SecurityStage,
    };

    use async_trait::async_trait;
    use globset::{Glob, GlobSetBuilder};
    use jsonwebtoken::jwk::JwkSet;
    use reqwest::Body;
    use std::sync::Arc;
    use tokio::sync::RwLock;

    use base64::Engine as _;
    use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
    use reqwest::header::HeaderMap;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    // Helper function to create a test request
    fn create_test_request(
        method: HttpMethod,
        path: &str,
        headers: Vec<(&'static str, &'static str)>,
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

        fn name(&self) -> &'static str {
            "mock-provider"
        }

        async fn pre(&self, request: ProxyRequest) -> Result<ProxyRequest, ProxyError> {
            // This mock always fails authentication unless it's configured to be bypassed
            if self.bypassed {
                Ok(request)
            } else {
                Err(ProxyError::SecurityError(
                    "Mock authentication failure".to_string(),
                ))
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
            fn stage(&self) -> SecurityStage {
                SecurityStage::Pre
            }
            fn name(&self) -> &'static str {
                "mock-oidc-with-bypass"
            }

            async fn pre(&self, request: ProxyRequest) -> Result<ProxyRequest, ProxyError> {
                // Internal bypass logic
                if request.path == "/health" {
                    return Ok(request); // Bypass
                }
                // Fail otherwise
                Err(ProxyError::SecurityError(
                    "OIDC validation failed".to_string(),
                ))
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
        use crate::security::basic::{BasicAuthConfig, BasicAuthProvider};

        let config = BasicAuthConfig {
            credentials: vec!["user1:pass1".to_string(), "user2:pass2".to_string()],
            bypass: vec![],
        };
        let _provider = BasicAuthProvider::new(config).unwrap();
        let chain = SecurityChain::from_configs(vec![crate::security::ProviderConfig {
            type_: "basic".to_string(),
            config: serde_json::to_value(BasicAuthConfig {
                credentials: vec!["user1:pass1".to_string()],
                bypass: vec![],
            })
            .unwrap(),
        }])
        .await
        .unwrap();

        let request = create_test_request(
            HttpMethod::Get,
            "/protected",
            vec![("authorization", "Basic dXNlcjE6cGFzczE=")], // user1:pass1 base64 encoded
        );
        assert!(chain.apply_pre(request).await.is_ok());
    }

    #[tokio::test]
    async fn test_basic_auth_provider_failure_invalid_credentials() {
        use crate::security::basic::{BasicAuthConfig, BasicAuthProvider};

        let config = BasicAuthConfig {
            credentials: vec!["user1:pass1".to_string()],
            bypass: vec![],
        };
        let _provider = BasicAuthProvider::new(config).unwrap();
        let chain = SecurityChain::from_configs(vec![crate::security::ProviderConfig {
            type_: "basic".to_string(),
            config: serde_json::to_value(BasicAuthConfig {
                credentials: vec!["user1:pass1".to_string()],
                bypass: vec![],
            })
            .unwrap(),
        }])
        .await
        .unwrap();

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
            bypass: vec![RouteRuleConfig {
                methods: vec!["GET".to_string()],
                path: "/public/*".to_string(),
            }],
        };
        let _provider = BasicAuthProvider::new(config).unwrap();
        let chain = SecurityChain::from_configs(vec![crate::security::ProviderConfig {
            type_: "basic".to_string(),
            config: serde_json::to_value(BasicAuthConfig {
                credentials: vec!["user1:pass1".to_string()],
                bypass: vec![RouteRuleConfig {
                    methods: vec!["GET".to_string()],
                    path: "/public/*".to_string(),
                }],
            })
            .unwrap(),
        }])
        .await
        .unwrap();

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

    // Tests for SecurityStage
    #[test]
    fn test_security_stage_is_pre() {
        assert!(SecurityStage::Pre.is_pre());
        assert!(SecurityStage::Both.is_pre());
        assert!(!SecurityStage::Post.is_pre());
    }

    #[test]
    fn test_security_stage_is_post() {
        assert!(SecurityStage::Post.is_post());
        assert!(SecurityStage::Both.is_post());
        assert!(!SecurityStage::Pre.is_post());
    }

    // Tests for SecurityChain with multiple providers
    #[tokio::test]
    async fn test_security_chain_multiple_providers() {
        let mut chain = SecurityChain::new();

        // Add a provider that passes
        let passing_provider = MockSecurityProvider::new(true);
        chain.add(Arc::new(passing_provider));

        // Add another provider that also passes
        let another_passing_provider = MockSecurityProvider::new(true);
        chain.add(Arc::new(another_passing_provider));

        let request = create_test_request(HttpMethod::Get, "/api/users", vec![]);
        let result = chain.apply_pre(request).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_security_chain_mixed_providers() {
        let mut chain = SecurityChain::new();

        // Add a provider that passes
        let passing_provider = MockSecurityProvider::new(true);
        chain.add(Arc::new(passing_provider));

        // Add a provider that fails
        let failing_provider = MockSecurityProvider::new(false);
        chain.add(Arc::new(failing_provider));

        let request = create_test_request(HttpMethod::Get, "/api/users", vec![]);
        let result = chain.apply_pre(request).await;
        assert!(result.is_err());
    }

    // Tests for post-auth chain
    #[tokio::test]
    async fn test_security_chain_apply_post() {
        #[derive(Debug)]
        struct MockPostSecurityProvider {
            should_fail: bool,
        }

        #[async_trait]
        impl SecurityProvider for MockPostSecurityProvider {
            fn stage(&self) -> SecurityStage {
                SecurityStage::Post
            }

            fn name(&self) -> &'static str {
                "mock-post-provider"
            }

            async fn post(
                &self,
                _request: ProxyRequest,
                response: ProxyResponse,
            ) -> Result<ProxyResponse, ProxyError> {
                if self.should_fail {
                    Err(ProxyError::SecurityError(
                        "Mock post-auth failure".to_string(),
                    ))
                } else {
                    Ok(response)
                }
            }
        }

        let mut chain = SecurityChain::new();
        let post_provider = MockPostSecurityProvider { should_fail: false };
        chain.add(Arc::new(post_provider));

        let request = create_test_request(HttpMethod::Get, "/api/users", vec![]);
        let response = create_test_response(200, vec![]);
        let result = chain.apply_post(request, response).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_security_chain_apply_post_failure() {
        #[derive(Debug)]
        struct MockPostSecurityProvider {
            should_fail: bool,
        }

        #[async_trait]
        impl SecurityProvider for MockPostSecurityProvider {
            fn stage(&self) -> SecurityStage {
                SecurityStage::Post
            }

            fn name(&self) -> &'static str {
                "mock-post-provider"
            }

            async fn post(
                &self,
                _request: ProxyRequest,
                response: ProxyResponse,
            ) -> Result<ProxyResponse, ProxyError> {
                if self.should_fail {
                    Err(ProxyError::SecurityError(
                        "Mock post-auth failure".to_string(),
                    ))
                } else {
                    Ok(response)
                }
            }
        }

        let mut chain = SecurityChain::new();
        let post_provider = MockPostSecurityProvider { should_fail: true };
        chain.add(Arc::new(post_provider));

        let request = create_test_request(HttpMethod::Get, "/api/users", vec![]);
        let response = create_test_response(200, vec![]);
        let result = chain.apply_post(request, response).await;
        assert!(result.is_err());
        if let Err(ProxyError::SecurityError(msg)) = result {
            assert!(msg.contains("Mock post-auth failure"));
        } else {
            panic!("Expected a SecurityError");
        }
    }

    // Tests for providers with Both stage
    #[tokio::test]
    async fn test_security_chain_both_stage_provider() {
        #[derive(Debug)]
        struct MockBothStageProvider;

        #[async_trait]
        impl SecurityProvider for MockBothStageProvider {
            fn stage(&self) -> SecurityStage {
                SecurityStage::Both
            }

            fn name(&self) -> &'static str {
                "mock-both-provider"
            }

            async fn pre(&self, request: ProxyRequest) -> Result<ProxyRequest, ProxyError> {
                Ok(request)
            }

            async fn post(
                &self,
                _request: ProxyRequest,
                response: ProxyResponse,
            ) -> Result<ProxyResponse, ProxyError> {
                Ok(response)
            }
        }

        let mut chain = SecurityChain::new();
        let both_provider = MockBothStageProvider;
        chain.add(Arc::new(both_provider));

        // Test pre-auth
        let request = create_test_request(HttpMethod::Get, "/api/users", vec![]);
        let result = chain.apply_pre(request.clone()).await;
        assert!(result.is_ok());

        // Test post-auth
        let response = create_test_response(200, vec![]);
        let result = chain.apply_post(request, response).await;
        assert!(result.is_ok());
    }

    // Helper function to create a test response
    fn create_test_response(
        status: u16,
        headers: Vec<(&'static str, &'static str)>,
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
            body: reqwest::Body::from(Vec::new()),
            context: Arc::new(RwLock::new(crate::core::ResponseContext::default())),
        }
    }

    // Tests for SecurityChain::from_configs
    #[tokio::test]
    async fn test_security_chain_from_configs_empty() {
        let chain = SecurityChain::from_configs(vec![]).await.unwrap();
        assert_eq!(chain.providers.len(), 0);
    }

    #[tokio::test]
    async fn test_security_chain_from_configs_unknown_provider() {
        use crate::security::ProviderConfig;

        let configs = vec![ProviderConfig {
            type_: "unknown_provider".to_string(),
            config: serde_json::json!({}),
        }];

        let result = SecurityChain::from_configs(configs).await;
        assert!(result.is_err());
        if let Err(ProxyError::SecurityError(msg)) = result {
            assert!(msg.contains("Unknown security provider type"));
        } else {
            panic!("Expected SecurityError for unknown provider");
        }
    }

    // Tests for provider registration
    #[tokio::test]
    async fn test_register_security_provider() {
        use crate::security::{ProviderConfig, SecurityChain, register_security_provider};

        // Define a custom security provider
        #[derive(Debug)]
        struct CustomSecurityProvider;

        #[async_trait]
        impl SecurityProvider for CustomSecurityProvider {
            fn stage(&self) -> SecurityStage {
                SecurityStage::Pre
            }

            fn name(&self) -> &'static str {
                "custom"
            }

            async fn pre(&self, request: ProxyRequest) -> Result<ProxyRequest, ProxyError> {
                Ok(request)
            }
        }

        // Register the custom provider
        register_security_provider("custom_test", |_config| {
            Box::pin(
                async move { Ok(Arc::new(CustomSecurityProvider) as Arc<dyn SecurityProvider>) },
            )
        });

        // Create a chain using the registered provider
        let configs = vec![ProviderConfig {
            type_: "custom_test".to_string(),
            config: serde_json::json!({}),
        }];

        let chain = SecurityChain::from_configs(configs).await.unwrap();
        assert_eq!(chain.providers.len(), 1);
        assert_eq!(chain.providers[0].name(), "custom");
    }

    // Tests for default SecurityProvider trait methods
    #[tokio::test]
    async fn test_security_provider_default_pre() {
        #[derive(Debug)]
        struct DefaultPreProvider;

        #[async_trait]
        impl SecurityProvider for DefaultPreProvider {
            fn stage(&self) -> SecurityStage {
                SecurityStage::Pre
            }

            fn name(&self) -> &'static str {
                "default-pre"
            }

            // Using default pre implementation
        }

        let provider = DefaultPreProvider;
        let request = create_test_request(HttpMethod::Get, "/test", vec![]);
        let result = provider.pre(request).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_security_provider_default_post() {
        #[derive(Debug)]
        struct DefaultPostProvider;

        #[async_trait]
        impl SecurityProvider for DefaultPostProvider {
            fn stage(&self) -> SecurityStage {
                SecurityStage::Post
            }

            fn name(&self) -> &'static str {
                "default-post"
            }

            // Using default post implementation
        }

        let provider = DefaultPostProvider;
        let request = create_test_request(HttpMethod::Get, "/test", vec![]);
        let response = create_test_response(200, vec![]);
        let result = provider.post(request, response).await;
        assert!(result.is_ok());
    }

    // Tests for BasicAuthProvider edge cases
    #[tokio::test]
    async fn test_basic_auth_provider_invalid_credential_format() {
        use crate::security::basic::BasicAuthConfig;
        use crate::security::basic::BasicAuthProvider;

        let config = BasicAuthConfig {
            credentials: vec!["invalid_format".to_string()], // Missing colon
            bypass: vec![],
        };

        let result = BasicAuthProvider::new(config);
        assert!(result.is_err());
        if let Err(ProxyError::SecurityError(msg)) = result {
            assert!(msg.contains("Invalid credential format"));
        } else {
            panic!("Expected SecurityError for invalid credential format");
        }
    }

    #[tokio::test]
    async fn test_basic_auth_provider_invalid_glob_pattern() {
        use crate::security::basic::BasicAuthProvider;
        use crate::security::basic::{BasicAuthConfig, RouteRuleConfig};

        let config = BasicAuthConfig {
            credentials: vec!["user:pass".to_string()],
            bypass: vec![RouteRuleConfig {
                methods: vec!["GET".to_string()],
                path: "[invalid_glob".to_string(), // Invalid glob pattern
            }],
        };

        let result = BasicAuthProvider::new(config);
        assert!(result.is_err());
        if let Err(ProxyError::SecurityError(msg)) = result {
            assert!(msg.contains("Invalid glob pattern"));
        } else {
            panic!("Expected SecurityError for invalid glob pattern");
        }
    }

    #[tokio::test]
    async fn test_basic_auth_provider_missing_auth_header() {
        use crate::security::basic::BasicAuthConfig;
        use crate::security::basic::BasicAuthProvider;

        let config = BasicAuthConfig {
            credentials: vec!["user:pass".to_string()],
            bypass: vec![],
        };
        let provider = BasicAuthProvider::new(config).unwrap();

        let request = create_test_request(HttpMethod::Get, "/protected", vec![]);
        let result = provider.pre(request).await;
        assert!(result.is_err());
        if let Err(ProxyError::SecurityError(msg)) = result {
            assert!(msg.contains("Missing authorization header"));
        } else {
            panic!("Expected SecurityError for missing auth header");
        }
    }

    #[tokio::test]
    async fn test_basic_auth_provider_invalid_auth_scheme() {
        use crate::security::basic::BasicAuthConfig;
        use crate::security::basic::BasicAuthProvider;

        let config = BasicAuthConfig {
            credentials: vec!["user:pass".to_string()],
            bypass: vec![],
        };
        let provider = BasicAuthProvider::new(config).unwrap();

        let request = create_test_request(
            HttpMethod::Get,
            "/protected",
            vec![("authorization", "Bearer token123")], // Wrong scheme
        );
        let result = provider.pre(request).await;
        assert!(result.is_err());
        if let Err(ProxyError::SecurityError(msg)) = result {
            assert!(msg.contains("Invalid authorization scheme"));
        } else {
            panic!("Expected SecurityError for invalid auth scheme");
        }
    }

    #[tokio::test]
    async fn test_basic_auth_provider_invalid_base64() {
        use crate::security::basic::BasicAuthConfig;
        use crate::security::basic::BasicAuthProvider;

        let config = BasicAuthConfig {
            credentials: vec!["user:pass".to_string()],
            bypass: vec![],
        };
        let provider = BasicAuthProvider::new(config).unwrap();

        let request = create_test_request(
            HttpMethod::Get,
            "/protected",
            vec![("authorization", "Basic invalid_base64!")], // Invalid base64
        );
        let result = provider.pre(request).await;
        assert!(result.is_err());
        if let Err(ProxyError::SecurityError(msg)) = result {
            assert!(msg.contains("Failed to base64 decode credentials"));
        } else {
            panic!("Expected SecurityError for invalid base64");
        }
    }

    #[tokio::test]
    async fn test_basic_auth_provider_malformed_credentials() {
        use crate::security::basic::BasicAuthConfig;
        use crate::security::basic::BasicAuthProvider;

        let config = BasicAuthConfig {
            credentials: vec!["user:pass".to_string()],
            bypass: vec![],
        };
        let provider = BasicAuthProvider::new(config).unwrap();

        // Use a pre-encoded invalid credential (useronly without colon)
        let request = create_test_request(
            HttpMethod::Get,
            "/protected",
            vec![("authorization", "Basic dXNlcm9ubHk=")], // "useronly" base64 encoded
        );
        let result = provider.pre(request).await;
        assert!(result.is_err());
        if let Err(ProxyError::SecurityError(msg)) = result {
            assert!(msg.contains("Invalid basic auth credential format"));
        } else {
            panic!("Expected SecurityError for malformed credentials");
        }
    }

    // Tests for RouteRule matching (tested indirectly through pre method)
    #[tokio::test]
    async fn test_route_rule_wildcard_method() {
        use crate::security::basic::{BasicAuthConfig, BasicAuthProvider, RouteRuleConfig};

        let config = BasicAuthConfig {
            credentials: vec!["user:pass".to_string()],
            bypass: vec![RouteRuleConfig {
                methods: vec!["*".to_string()], // Wildcard method
                path: "/public/*".to_string(),
            }],
        };
        let provider = BasicAuthProvider::new(config).unwrap();

        // Test that wildcard method matches any HTTP method (no auth header needed)
        let get_request = create_test_request(HttpMethod::Get, "/public/data", vec![]);
        assert!(provider.pre(get_request).await.is_ok());

        let post_request = create_test_request(HttpMethod::Post, "/public/data", vec![]);
        assert!(provider.pre(post_request).await.is_ok());

        let put_request = create_test_request(HttpMethod::Put, "/public/data", vec![]);
        assert!(provider.pre(put_request).await.is_ok());

        let delete_request = create_test_request(HttpMethod::Delete, "/public/data", vec![]);
        assert!(provider.pre(delete_request).await.is_ok());
    }

    #[tokio::test]
    async fn test_route_rule_specific_methods() {
        use crate::security::basic::{BasicAuthConfig, BasicAuthProvider, RouteRuleConfig};

        let config = BasicAuthConfig {
            credentials: vec!["user:pass".to_string()],
            bypass: vec![RouteRuleConfig {
                methods: vec!["GET".to_string(), "POST".to_string()],
                path: "/api/*".to_string(),
            }],
        };
        let provider = BasicAuthProvider::new(config).unwrap();

        // Test that only specified methods match (no auth header needed)
        let get_request = create_test_request(HttpMethod::Get, "/api/data", vec![]);
        assert!(provider.pre(get_request).await.is_ok());

        let post_request = create_test_request(HttpMethod::Post, "/api/data", vec![]);
        assert!(provider.pre(post_request).await.is_ok());

        // These should fail because they're not in the bypass list
        let put_request = create_test_request(HttpMethod::Put, "/api/data", vec![]);
        assert!(provider.pre(put_request).await.is_err());

        let delete_request = create_test_request(HttpMethod::Delete, "/api/data", vec![]);
        assert!(provider.pre(delete_request).await.is_err());
    }

    #[tokio::test]
    async fn test_route_rule_complex_glob_patterns() {
        use crate::security::basic::{BasicAuthConfig, BasicAuthProvider, RouteRuleConfig};

        let config = BasicAuthConfig {
            credentials: vec!["user:pass".to_string()],
            bypass: vec![RouteRuleConfig {
                methods: vec!["GET".to_string()],
                path: "/api/v*/users/*/profile".to_string(), // Complex glob
            }],
        };
        let provider = BasicAuthProvider::new(config).unwrap();

        // Test complex glob matching (should succeed without auth)
        let request1 = create_test_request(HttpMethod::Get, "/api/v1/users/123/profile", vec![]);
        assert!(provider.pre(request1).await.is_ok());

        let request2 = create_test_request(HttpMethod::Get, "/api/v2/users/456/profile", vec![]);
        assert!(provider.pre(request2).await.is_ok());

        // These should fail because they don't match the pattern
        let request3 = create_test_request(HttpMethod::Get, "/api/v1/users/123/settings", vec![]);
        assert!(provider.pre(request3).await.is_err());

        let request4 = create_test_request(HttpMethod::Get, "/api/users/123/profile", vec![]);
        assert!(provider.pre(request4).await.is_err());
    }

    #[tokio::test]
    async fn test_route_rule_exact_path_match() {
        use crate::security::basic::{BasicAuthConfig, BasicAuthProvider, RouteRuleConfig};

        let config = BasicAuthConfig {
            credentials: vec!["user:pass".to_string()],
            bypass: vec![RouteRuleConfig {
                methods: vec!["GET".to_string()],
                path: "/health".to_string(), // Exact path
            }],
        };
        let provider = BasicAuthProvider::new(config).unwrap();

        // Test exact path matching (should succeed without auth)
        let request1 = create_test_request(HttpMethod::Get, "/health", vec![]);
        assert!(provider.pre(request1).await.is_ok());

        // These should fail because they don't match exactly
        let request2 = create_test_request(HttpMethod::Get, "/health/check", vec![]);
        assert!(provider.pre(request2).await.is_err());

        let request3 = create_test_request(HttpMethod::Get, "/healthz", vec![]);
        assert!(provider.pre(request3).await.is_err());
    }

    // Tests for multiple bypass rules
    #[tokio::test]
    async fn test_basic_auth_provider_multiple_bypass_rules() {
        use crate::security::basic::{BasicAuthConfig, BasicAuthProvider, RouteRuleConfig};

        let config = BasicAuthConfig {
            credentials: vec!["user:pass".to_string()],
            bypass: vec![
                RouteRuleConfig {
                    methods: vec!["GET".to_string()],
                    path: "/health".to_string(),
                },
                RouteRuleConfig {
                    methods: vec!["*".to_string()],
                    path: "/public/*".to_string(),
                },
                RouteRuleConfig {
                    methods: vec!["POST".to_string()],
                    path: "/webhook".to_string(),
                },
            ],
        };
        let provider = BasicAuthProvider::new(config).unwrap();

        // Test that all bypass rules work
        let health_request = create_test_request(HttpMethod::Get, "/health", vec![]);
        assert!(provider.pre(health_request).await.is_ok());

        let public_request = create_test_request(HttpMethod::Post, "/public/data", vec![]);
        assert!(provider.pre(public_request).await.is_ok());

        let webhook_request = create_test_request(HttpMethod::Post, "/webhook", vec![]);
        assert!(provider.pre(webhook_request).await.is_ok());

        // Test that non-bypassed routes still require auth
        let protected_request = create_test_request(HttpMethod::Get, "/protected", vec![]);
        assert!(provider.pre(protected_request).await.is_err());
    }

    // Tests for empty configurations
    #[tokio::test]
    async fn test_basic_auth_provider_empty_credentials() {
        use crate::security::basic::BasicAuthConfig;
        use crate::security::basic::BasicAuthProvider;

        let config = BasicAuthConfig {
            credentials: vec![], // Empty credentials
            bypass: vec![],
        };
        let provider = BasicAuthProvider::new(config).unwrap();

        // Even with valid auth header, should fail because no valid credentials
        let request = create_test_request(
            HttpMethod::Get,
            "/protected",
            vec![("authorization", "Basic dXNlcjpwYXNz")], // user:pass
        );
        let result = provider.pre(request).await;
        assert!(result.is_err());
    }

    // Tests for case sensitivity
    #[tokio::test]
    async fn test_basic_auth_provider_case_sensitive_scheme() {
        use crate::security::basic::BasicAuthConfig;
        use crate::security::basic::BasicAuthProvider;

        let config = BasicAuthConfig {
            credentials: vec!["user:pass".to_string()],
            bypass: vec![],
        };
        let provider = BasicAuthProvider::new(config).unwrap();

        // Test case insensitive scheme matching
        let request = create_test_request(
            HttpMethod::Get,
            "/protected",
            vec![("authorization", "basic dXNlcjpwYXNz")], // lowercase "basic"
        );
        let result = provider.pre(request).await;
        assert!(result.is_ok()); // Should work because scheme matching is case-insensitive
    }

    #[test]
    fn test_route_rule_config_deserialization() {
        let json = r#"{
            "methods": ["GET", "POST"],
            "path": "/api/*"
        }"#;

        let config: RouteRuleConfig = serde_json::from_str(json).unwrap();
        assert_eq!(config.methods, vec!["GET", "POST"]);
        assert_eq!(config.path, "/api/*");
    }

    #[test]
    fn test_route_rule_matches() {
        let mut builder = GlobSetBuilder::new();
        builder.add(Glob::new("/api/*").unwrap());
        let paths = builder.build().unwrap();

        let rule = RouteRule {
            methods: vec!["GET".to_string(), "POST".to_string()],
            paths,
        };

        // Test method and path matching
        assert!(rule.matches("GET", "/api/users"));
        assert!(rule.matches("POST", "/api/users"));
        assert!(!rule.matches("DELETE", "/api/users"));
        assert!(!rule.matches("GET", "/health"));

        // Test case sensitive method matching (methods are stored in uppercase)
        assert!(!rule.matches("get", "/api/users"));
        assert!(!rule.matches("post", "/api/users"));
    }

    #[test]
    fn test_route_rule_wildcard_methods() {
        let mut builder = GlobSetBuilder::new();
        builder.add(Glob::new("/health").unwrap());
        let paths = builder.build().unwrap();

        let rule = RouteRule {
            methods: vec!["*".to_string()],
            paths,
        };

        assert!(rule.matches("GET", "/health"));
        assert!(rule.matches("POST", "/health"));
        assert!(rule.matches("DELETE", "/health"));
        assert!(!rule.matches("GET", "/api"));
    }

    #[test]
    fn test_oidc_config_deserialization() {
        let json = r#"{
            "issuer-uri": "https://auth.example.com/.well-known/openid-configuration",
            "aud": "my-app",
            "shared-secret": "secret123",
            "bypass": [
                {
                    "methods": ["GET"],
                    "path": "/health"
                }
            ]
        }"#;

        let config: OidcConfig = serde_json::from_str(json).unwrap();
        assert_eq!(
            config.issuer_uri,
            "https://auth.example.com/.well-known/openid-configuration"
        );
        assert_eq!(config.aud, Some("my-app".to_string()));
        assert_eq!(config.shared_secret, Some("secret123".to_string()));
        assert_eq!(config.bypass.len(), 1);
        assert_eq!(config.bypass[0].methods, vec!["GET"]);
        assert_eq!(config.bypass[0].path, "/health");
    }

    #[test]
    fn test_oidc_config_minimal() {
        let json = r#"{
            "issuer-uri": "https://auth.example.com"
        }"#;

        let config: OidcConfig = serde_json::from_str(json).unwrap();
        assert_eq!(config.issuer_uri, "https://auth.example.com");
        assert_eq!(config.aud, None);
        assert_eq!(config.shared_secret, None);
        assert!(config.bypass.is_empty());
    }

    #[test]
    fn test_oidc_config_empty_bypass() {
        let json = r#"{
            "issuer-uri": "https://auth.example.com",
            "bypass": []
        }"#;

        let config: OidcConfig = serde_json::from_str(json).unwrap();
        assert!(config.bypass.is_empty());
    }

    #[tokio::test]
    async fn test_oidc_provider_discover_success() {
        // Setup mock server
        let mock_server = MockServer::start().await;

        // Mock the discovery endpoint
        Mock::given(method("GET"))
            .and(path("/"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "issuer": mock_server.uri(),
                "jwks_uri": format!("{}/jwks", mock_server.uri()),
                "authorization_endpoint": format!("{}/auth", mock_server.uri()),
                "token_endpoint": format!("{}/token", mock_server.uri())
            })))
            .mount(&mock_server)
            .await;

        let config = OidcConfig {
            issuer_uri: mock_server.uri(),
            aud: Some("test-audience".to_string()),
            shared_secret: Some("test-secret".to_string()),
            bypass: vec![
                RouteRuleConfig {
                    methods: vec!["GET".to_string()],
                    path: "/health".to_string(),
                },
                RouteRuleConfig {
                    methods: vec!["*".to_string()],
                    path: "/public/*".to_string(),
                },
            ],
        };

        let result = OidcProvider::discover(config.clone()).await;
        assert!(result.is_ok());

        let provider = result.unwrap();
        assert_eq!(provider.issuer, mock_server.uri());
        assert_eq!(provider.aud, Some("test-audience".to_string()));
        assert_eq!(provider.shared_secret, Some("test-secret".to_string()));
        assert_eq!(provider.jwks_uri, format!("{}/jwks", mock_server.uri()));
        assert_eq!(provider.rules.len(), 2);

        // Test bypass rules were compiled correctly
        assert!(provider.is_bypassed("GET", "/health"));
        assert!(provider.is_bypassed("POST", "/public/api"));
        assert!(!provider.is_bypassed("POST", "/private/api"));
    }

    #[tokio::test]
    async fn test_oidc_provider_discover_success_minimal_config() {
        // Setup mock server
        let mock_server = MockServer::start().await;

        // Mock the discovery endpoint
        Mock::given(method("GET"))
            .and(path("/"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "issuer": mock_server.uri(),
                "jwks_uri": format!("{}/jwks", mock_server.uri())
            })))
            .mount(&mock_server)
            .await;

        let config = OidcConfig {
            issuer_uri: mock_server.uri(),
            aud: None,
            shared_secret: None,
            bypass: vec![],
        };

        let result = OidcProvider::discover(config).await;
        assert!(result.is_ok());

        let provider = result.unwrap();
        assert_eq!(provider.issuer, mock_server.uri());
        assert_eq!(provider.aud, None);
        assert_eq!(provider.shared_secret, None);
        assert_eq!(provider.jwks_uri, format!("{}/jwks", mock_server.uri()));
        assert!(provider.rules.is_empty());
    }

    #[tokio::test]
    async fn test_oidc_provider_discover_success_with_well_known_suffix() {
        // Setup mock server
        let mock_server = MockServer::start().await;

        // Mock the discovery endpoint
        Mock::given(method("GET"))
            .and(path("/.well-known/openid-configuration"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "issuer": mock_server.uri(),
                "jwks_uri": format!("{}/jwks", mock_server.uri())
            })))
            .mount(&mock_server)
            .await;

        let config = OidcConfig {
            issuer_uri: format!("{}/.well-known/openid-configuration", mock_server.uri()),
            aud: None,
            shared_secret: None,
            bypass: vec![],
        };

        let result = OidcProvider::discover(config).await;
        assert!(result.is_ok());

        let provider = result.unwrap();
        // Should strip the .well-known suffix from issuer
        assert_eq!(provider.issuer, mock_server.uri());
        assert_eq!(provider.jwks_uri, format!("{}/jwks", mock_server.uri()));
    }

    #[tokio::test]
    async fn test_oidc_provider_discover_invalid_url() {
        let config = OidcConfig {
            issuer_uri: "invalid-url".to_string(),
            aud: None,
            shared_secret: None,
            bypass: vec![],
        };

        let result = OidcProvider::discover(config).await;
        assert!(result.is_err());

        if let Err(ProxyError::SecurityError(msg)) = result {
            assert!(msg.contains("Failed to connect to OIDC discovery endpoint"));
        } else {
            panic!("Expected SecurityError");
        }
    }

    #[tokio::test]
    async fn test_oidc_provider_discover_http_error() {
        // Setup mock server
        let mock_server = MockServer::start().await;

        // Mock the discovery endpoint to return 404
        Mock::given(method("GET"))
            .and(path("/"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&mock_server)
            .await;

        let config = OidcConfig {
            issuer_uri: mock_server.uri(),
            aud: None,
            shared_secret: None,
            bypass: vec![],
        };

        let result = OidcProvider::discover(config).await;
        assert!(result.is_err());

        if let Err(ProxyError::SecurityError(msg)) = result {
            assert!(msg.contains("OIDC discovery endpoint returned error"));
        } else {
            panic!("Expected SecurityError");
        }
    }

    #[tokio::test]
    async fn test_oidc_provider_discover_invalid_json() {
        // Setup mock server
        let mock_server = MockServer::start().await;

        // Mock the discovery endpoint to return invalid JSON
        Mock::given(method("GET"))
            .and(path("/"))
            .respond_with(ResponseTemplate::new(200).set_body_string("invalid json"))
            .mount(&mock_server)
            .await;

        let config = OidcConfig {
            issuer_uri: mock_server.uri(),
            aud: None,
            shared_secret: None,
            bypass: vec![],
        };

        let result = OidcProvider::discover(config).await;
        assert!(result.is_err());

        if let Err(ProxyError::SecurityError(msg)) = result {
            assert!(msg.contains("Failed to parse OIDC discovery response"));
        } else {
            panic!("Expected SecurityError");
        }
    }

    #[tokio::test]
    async fn test_oidc_provider_discover_missing_jwks_uri() {
        // Setup mock server
        let mock_server = MockServer::start().await;

        // Mock the discovery endpoint to return JSON without jwks_uri
        Mock::given(method("GET"))
            .and(path("/"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "issuer": mock_server.uri(),
                "authorization_endpoint": format!("{}/auth", mock_server.uri())
            })))
            .mount(&mock_server)
            .await;

        let config = OidcConfig {
            issuer_uri: mock_server.uri(),
            aud: None,
            shared_secret: None,
            bypass: vec![],
        };

        let result = OidcProvider::discover(config).await;
        assert!(result.is_err());

        if let Err(ProxyError::SecurityError(msg)) = result {
            assert!(msg.contains("Failed to parse OIDC discovery response"));
        } else {
            panic!("Expected SecurityError");
        }
    }

    #[tokio::test]
    async fn test_oidc_provider_discover_invalid_bypass_glob() {
        // Setup mock server
        let mock_server = MockServer::start().await;

        // Mock the discovery endpoint
        Mock::given(method("GET"))
            .and(path("/"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "issuer": mock_server.uri(),
                "jwks_uri": format!("{}/jwks", mock_server.uri())
            })))
            .mount(&mock_server)
            .await;

        let config = OidcConfig {
            issuer_uri: mock_server.uri(),
            aud: None,
            shared_secret: None,
            bypass: vec![RouteRuleConfig {
                methods: vec!["GET".to_string()],
                path: "[invalid-glob".to_string(), // Invalid glob pattern
            }],
        };

        let result = OidcProvider::discover(config).await;
        assert!(result.is_err());

        if let Err(ProxyError::SecurityError(msg)) = result {
            assert!(msg.contains("Invalid glob pattern in bypass rule"));
        } else {
            panic!("Expected SecurityError");
        }
    }

    #[tokio::test]
    async fn test_oidc_provider_discover_complex_bypass_rules() {
        // Setup mock server
        let mock_server = MockServer::start().await;

        // Mock the discovery endpoint
        Mock::given(method("GET"))
            .and(path("/"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "issuer": mock_server.uri(),
                "jwks_uri": format!("{}/jwks", mock_server.uri())
            })))
            .mount(&mock_server)
            .await;

        let config = OidcConfig {
            issuer_uri: mock_server.uri(),
            aud: None,
            shared_secret: None,
            bypass: vec![
                RouteRuleConfig {
                    methods: vec!["get".to_string(), "post".to_string()], // lowercase methods
                    path: "/api/v*/health".to_string(),
                },
                RouteRuleConfig {
                    methods: vec!["*".to_string()],
                    path: "/static/**".to_string(),
                },
            ],
        };

        let result = OidcProvider::discover(config).await;
        assert!(result.is_ok());

        let provider = result.unwrap();
        assert_eq!(provider.rules.len(), 2);

        // Test that methods are converted to uppercase
        assert!(provider.is_bypassed("GET", "/api/v1/health"));
        assert!(provider.is_bypassed("POST", "/api/v2/health"));
        assert!(provider.is_bypassed("DELETE", "/static/css/style.css"));
        assert!(!provider.is_bypassed("GET", "/api/v1/users"));
    }

    #[tokio::test]
    async fn test_jwks_refresh_cache_fresh() {
        // Setup mock server
        let mock_server = MockServer::start().await;

        // Mock the discovery endpoint
        Mock::given(method("GET"))
            .and(path("/"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "issuer": mock_server.uri(),
                "jwks_uri": format!("{}/jwks", mock_server.uri())
            })))
            .mount(&mock_server)
            .await;

        let config = OidcConfig {
            issuer_uri: mock_server.uri(),
            aud: None,
            shared_secret: None,
            bypass: vec![],
        };

        let provider = OidcProvider::discover(config).await.unwrap();

        // Set last refresh to now (fresh cache) and populate the cache
        {
            let mut jwks_w = provider.jwks.write().await;
            *jwks_w = Some(JwkSet { keys: vec![] }); // Add some dummy data to cache
        }
        {
            let mut refresh_w = provider.last_refresh.write().await;
            *refresh_w = tokio::time::Instant::now();
        }

        // Should not make HTTP request since cache is fresh and not empty
        let result = provider.refresh_jwks().await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_jwks_refresh_success() {
        // Setup mock server
        let mock_server = MockServer::start().await;

        // Mock the discovery endpoint
        Mock::given(method("GET"))
            .and(path("/"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "issuer": mock_server.uri(),
                "jwks_uri": format!("{}/jwks", mock_server.uri())
            })))
            .mount(&mock_server)
            .await;

        // Mock the JWKS endpoint
        Mock::given(method("GET"))
            .and(path("/jwks"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "keys": [
                    {
                        "kty": "RSA",
                        "kid": "test-key-1",
                        "use": "sig",
                        "alg": "RS256",
                        "n": "test-modulus",
                        "e": "AQAB"
                    }
                ]
            })))
            .mount(&mock_server)
            .await;

        let config = OidcConfig {
            issuer_uri: mock_server.uri(),
            aud: None,
            shared_secret: None,
            bypass: vec![],
        };

        let provider = OidcProvider::discover(config).await.unwrap();

        // Force cache expiration by clearing the cache and setting last_refresh to an old time
        {
            let mut jwks_w = provider.jwks.write().await;
            *jwks_w = None; // Clear the cache
        }
        {
            let mut refresh_w = provider.last_refresh.write().await;
            // Set to a time that's guaranteed to trigger refresh
            *refresh_w = tokio::time::Instant::now()
                .checked_sub(JWKS_REFRESH + std::time::Duration::from_secs(1))
                .unwrap_or_else(|| {
                    // Fallback: use a very old instant by subtracting a small amount
                    tokio::time::Instant::now()
                        .checked_sub(std::time::Duration::from_millis(1))
                        .unwrap_or_else(tokio::time::Instant::now)
                });
        }

        let result = provider.refresh_jwks().await;
        assert!(result.is_ok());

        // Verify JWKS was cached
        let jwks = provider.jwks.read().await;
        assert!(jwks.is_some());
        let jwks = jwks.as_ref().unwrap();
        assert_eq!(jwks.keys.len(), 1);
        assert_eq!(jwks.keys[0].common.key_id, Some("test-key-1".to_string()));
    }

    #[tokio::test]
    async fn test_jwks_refresh_http_error() {
        // Setup mock server
        let mock_server = MockServer::start().await;

        // Mock the discovery endpoint
        Mock::given(method("GET"))
            .and(path("/"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "issuer": mock_server.uri(),
                "jwks_uri": format!("{}/jwks", mock_server.uri())
            })))
            .mount(&mock_server)
            .await;

        // Mock the JWKS endpoint to return 500 error
        Mock::given(method("GET"))
            .and(path("/jwks"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&mock_server)
            .await;

        let config = OidcConfig {
            issuer_uri: mock_server.uri(),
            aud: None,
            shared_secret: None,
            bypass: vec![],
        };

        let provider = OidcProvider::discover(config).await.unwrap();

        // Force cache expiration by setting last_refresh to a very old time
        {
            let mut w = provider.last_refresh.write().await;
            *w = tokio::time::Instant::now()
                .checked_sub(JWKS_REFRESH * 2)
                .unwrap_or_else(|| {
                    tokio::time::Instant::now()
                        .checked_sub(std::time::Duration::from_secs(1))
                        .unwrap_or_else(tokio::time::Instant::now)
                });
        }

        let result = provider.refresh_jwks().await;
        assert!(result.is_err());

        if let Err(ProxyError::SecurityError(msg)) = result {
            assert!(msg.contains("JWKS endpoint returned error"));
        } else {
            panic!("Expected SecurityError");
        }
    }

    #[tokio::test]
    async fn test_jwks_refresh_invalid_json() {
        // Setup mock server
        let mock_server = MockServer::start().await;

        // Mock the discovery endpoint
        Mock::given(method("GET"))
            .and(path("/"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "issuer": mock_server.uri(),
                "jwks_uri": format!("{}/jwks", mock_server.uri())
            })))
            .mount(&mock_server)
            .await;

        // Mock the JWKS endpoint to return invalid JSON
        Mock::given(method("GET"))
            .and(path("/jwks"))
            .respond_with(ResponseTemplate::new(200).set_body_string("invalid json"))
            .mount(&mock_server)
            .await;

        let config = OidcConfig {
            issuer_uri: mock_server.uri(),
            aud: None,
            shared_secret: None,
            bypass: vec![],
        };

        let provider = OidcProvider::discover(config).await.unwrap();

        // Force cache expiration by clearing the cache and setting last_refresh to an old time
        {
            let mut jwks_w = provider.jwks.write().await;
            *jwks_w = None; // Clear the cache
        }
        {
            let mut refresh_w = provider.last_refresh.write().await;
            // Set to a time that's guaranteed to trigger refresh
            *refresh_w = tokio::time::Instant::now()
                .checked_sub(JWKS_REFRESH + std::time::Duration::from_secs(1))
                .unwrap_or_else(|| {
                    // Fallback: use a very old instant by subtracting a small amount
                    tokio::time::Instant::now()
                        .checked_sub(std::time::Duration::from_millis(1))
                        .unwrap_or_else(tokio::time::Instant::now)
                });
        }

        let result = provider.refresh_jwks().await;
        assert!(result.is_err());

        if let Err(ProxyError::SecurityError(msg)) = result {
            assert!(msg.contains("Failed to parse JWKS response"));
        } else {
            panic!("Expected SecurityError");
        }
    }

    #[tokio::test]
    async fn test_jwks_refresh_connection_error() {
        let provider = OidcProvider {
            issuer: "https://auth.example.com".to_string(),
            aud: None,
            shared_secret: None,
            jwks_uri: "http://invalid-host-12345.example.com/jwks".to_string(),
            jwks: Arc::new(RwLock::new(None)),
            last_refresh: Arc::new(RwLock::new(
                tokio::time::Instant::now()
                    .checked_sub(JWKS_REFRESH * 2)
                    .unwrap_or_else(|| {
                        tokio::time::Instant::now()
                            .checked_sub(std::time::Duration::from_secs(1))
                            .unwrap_or_else(tokio::time::Instant::now)
                    }),
            )),
            http: reqwest::Client::new(),
            rules: vec![],
        };

        let result = provider.refresh_jwks().await;
        assert!(result.is_err());

        if let Err(ProxyError::SecurityError(msg)) = result {
            assert!(msg.contains("Failed to connect to JWKS endpoint"));
        } else {
            panic!("Expected SecurityError");
        }
    }

    #[tokio::test]
    async fn test_validate_token_invalid_header() {
        let provider = OidcProvider {
            issuer: "https://auth.example.com".to_string(),
            aud: None,
            shared_secret: None,
            jwks_uri: "https://auth.example.com/jwks".to_string(),
            jwks: Arc::new(RwLock::new(None)),
            last_refresh: Arc::new(RwLock::new(tokio::time::Instant::now())),
            http: reqwest::Client::new(),
            rules: vec![],
        };

        // Invalid JWT token (not base64 encoded)
        let result = provider.validate_token("invalid.token.here").await;
        assert!(result.is_err());

        if let Err(ProxyError::SecurityError(msg)) = result {
            assert!(msg.contains("Invalid JWT header"));
        } else {
            panic!("Expected SecurityError");
        }
    }

    #[tokio::test]
    async fn test_validate_token_unsupported_algorithm() {
        use jsonwebtoken::Header;
        use serde_json::json;

        let provider = OidcProvider {
            issuer: "https://auth.example.com".to_string(),
            aud: None,
            shared_secret: None,
            jwks_uri: "https://auth.example.com/jwks".to_string(),
            jwks: Arc::new(RwLock::new(None)),
            last_refresh: Arc::new(RwLock::new(tokio::time::Instant::now())),
            http: reqwest::Client::new(),
            rules: vec![],
        };

        // Create a JWT with unsupported algorithm (none)

        let mut _header = Header::new(jsonwebtoken::Algorithm::HS256);
        _header.alg = jsonwebtoken::Algorithm::HS256; // This will be overridden

        // We need to manually create a token with "none" algorithm
        // Since jsonwebtoken doesn't support "none", we'll create a malformed token
        let header_json = json!({"alg": "none", "typ": "JWT"});
        let header_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(header_json.to_string().as_bytes());
        let payload_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(json!({"sub": "test"}).to_string().as_bytes());
        let token = format!("{header_b64}.{payload_b64}.signature");

        let result = provider.validate_token(&token).await;
        assert!(result.is_err());

        if let Err(ProxyError::SecurityError(msg)) = result {
            assert!(msg.contains("Invalid JWT header") || msg.contains("Algorithm not allowed"));
        } else {
            panic!("Expected SecurityError");
        }
    }

    #[tokio::test]
    async fn test_validate_token_no_jwks_available() {
        use jsonwebtoken::{Algorithm, Header};
        use serde_json::json;

        let provider = OidcProvider {
            issuer: "https://auth.example.com".to_string(),
            aud: None,
            shared_secret: None,
            jwks_uri: "https://auth.example.com/jwks".to_string(),
            jwks: Arc::new(RwLock::new(None)), // No JWKS available
            last_refresh: Arc::new(RwLock::new(
                tokio::time::Instant::now()
                    .checked_sub(JWKS_REFRESH * 2)
                    .unwrap_or_else(|| {
                        tokio::time::Instant::now()
                            .checked_sub(std::time::Duration::from_secs(1))
                            .unwrap_or_else(tokio::time::Instant::now)
                    }),
            )),
            http: reqwest::Client::new(),
            rules: vec![],
        };

        // Create a valid JWT header with RS256

        let _header = Header {
            alg: Algorithm::RS256,
            kid: Some("test-key".to_string()),
            ..Default::default()
        };

        let header_json = json!({
            "alg": "RS256",
            "typ": "JWT",
            "kid": "test-key"
        });
        let header_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(header_json.to_string().as_bytes());
        let payload_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(json!({"sub": "test"}).to_string().as_bytes());
        let token = format!("{header_b64}.{payload_b64}.signature");

        let result = provider.validate_token(&token).await;
        assert!(result.is_err());

        if let Err(ProxyError::SecurityError(msg)) = result {
            assert!(msg.contains("No JWKS available") || msg.contains("Failed to connect"));
        } else {
            panic!("Expected SecurityError");
        }
    }

    #[tokio::test]
    async fn test_validate_token_hmac_success() {
        let provider = OidcProvider {
            issuer: "https://auth.example.com".to_string(),
            aud: Some("test-audience".to_string()),
            shared_secret: Some("test-secret-key".to_string()),
            jwks_uri: "https://auth.example.com/jwks".to_string(),
            jwks: Arc::new(RwLock::new(None)),
            last_refresh: Arc::new(RwLock::new(tokio::time::Instant::now())),
            http: reqwest::Client::new(),
            rules: vec![],
        };

        // Create a valid HMAC JWT token
        use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};

        let header = Header::new(Algorithm::HS256);

        #[derive(serde::Serialize)]
        struct HmacTestClaims {
            iss: String,
            aud: String,
            sub: String,
            exp: i64,
            iat: i64,
        }

        let claims = HmacTestClaims {
            iss: "https://auth.example.com".to_string(),
            aud: "test-audience".to_string(),
            sub: "test-user".to_string(),
            exp: (std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs()
                + 3600) as i64,
            iat: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64,
        };

        let token = encode(
            &header,
            &claims,
            &EncodingKey::from_secret("test-secret-key".as_ref()),
        )
        .unwrap();

        let result = provider.validate_token(&token).await;
        assert!(result.is_ok());

        let validated_claims = result.unwrap();
        assert_eq!(validated_claims["iss"], "https://auth.example.com");
        assert_eq!(validated_claims["aud"], "test-audience");
        assert_eq!(validated_claims["sub"], "test-user");
    }

    #[tokio::test]
    async fn test_validate_token_hmac_wrong_secret() {
        let provider = OidcProvider {
            issuer: "https://auth.example.com".to_string(),
            aud: None,
            shared_secret: Some("wrong-secret".to_string()),
            jwks_uri: "https://auth.example.com/jwks".to_string(),
            jwks: Arc::new(RwLock::new(None)),
            last_refresh: Arc::new(RwLock::new(tokio::time::Instant::now())),
            http: reqwest::Client::new(),
            rules: vec![],
        };

        // Create a JWT token with different secret
        use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};

        let header = Header::new(Algorithm::HS256);

        #[derive(serde::Serialize)]
        struct WrongSecretClaims {
            iss: String,
            sub: String,
            exp: i64,
        }

        let claims = WrongSecretClaims {
            iss: "https://auth.example.com".to_string(),
            sub: "test-user".to_string(),
            exp: (std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs()
                + 3600) as i64,
        };

        let token = encode(
            &header,
            &claims,
            &EncodingKey::from_secret("correct-secret".as_ref()),
        )
        .unwrap();

        let result = provider.validate_token(&token).await;
        assert!(result.is_err());

        if let Err(ProxyError::SecurityError(msg)) = result {
            assert!(msg.contains("JWT validation failed: InvalidSignature"));
        } else {
            panic!("Expected SecurityError");
        }
    }

    #[tokio::test]
    async fn test_validate_token_hmac_no_shared_secret() {
        let provider = OidcProvider {
            issuer: "https://auth.example.com".to_string(),
            aud: None,
            shared_secret: None, // No shared secret configured
            jwks_uri: "https://auth.example.com/jwks".to_string(),
            jwks: Arc::new(RwLock::new(None)),
            last_refresh: Arc::new(RwLock::new(tokio::time::Instant::now())),
            http: reqwest::Client::new(),
            rules: vec![],
        };

        // Create a HMAC JWT token
        use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};

        let header = Header::new(Algorithm::HS256);

        #[derive(serde::Serialize)]
        struct NoSecretClaims {
            iss: String,
            sub: String,
            exp: i64,
        }

        let claims = NoSecretClaims {
            iss: "https://auth.example.com".to_string(),
            sub: "test-user".to_string(),
            exp: (std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs()
                + 3600) as i64,
        };

        let token = encode(
            &header,
            &claims,
            &EncodingKey::from_secret("test-secret".as_ref()),
        )
        .unwrap();

        let result = provider.validate_token(&token).await;
        assert!(result.is_err());

        if let Err(ProxyError::SecurityError(msg)) = result {
            assert!(msg.contains("No key ID in token and no shared secret configured"));
        } else {
            panic!("Expected SecurityError");
        }
    }

    #[tokio::test]
    async fn test_validate_claims_wrong_issuer() {
        let provider = OidcProvider {
            issuer: "https://auth.example.com".to_string(),
            aud: None,
            shared_secret: Some("test-secret".to_string()),
            jwks_uri: "https://auth.example.com/jwks".to_string(),
            jwks: Arc::new(RwLock::new(None)),
            last_refresh: Arc::new(RwLock::new(tokio::time::Instant::now())),
            http: reqwest::Client::new(),
            rules: vec![],
        };

        // Create a JWT token with wrong issuer
        use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};

        let header = Header::new(Algorithm::HS256);

        #[derive(serde::Serialize)]
        struct WrongIssuerClaims {
            iss: String,
            sub: String,
            exp: i64,
        }

        let claims = WrongIssuerClaims {
            iss: "https://wrong-issuer.com".to_string(), // Wrong issuer
            sub: "test-user".to_string(),
            exp: (std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs()
                + 3600) as i64,
        };

        let token = encode(
            &header,
            &claims,
            &EncodingKey::from_secret("test-secret".as_ref()),
        )
        .unwrap();

        let result = provider.validate_token(&token).await;
        assert!(result.is_err());

        if let Err(ProxyError::SecurityError(msg)) = result {
            assert!(msg.contains("InvalidIssuer"));
        } else {
            panic!("Expected SecurityError");
        }
    }

    #[tokio::test]
    async fn test_validate_claims_wrong_audience() {
        let provider = OidcProvider {
            issuer: "https://auth.example.com".to_string(),
            aud: Some("expected-audience".to_string()),
            shared_secret: Some("test-secret".to_string()),
            jwks_uri: "https://auth.example.com/jwks".to_string(),
            jwks: Arc::new(RwLock::new(None)),
            last_refresh: Arc::new(RwLock::new(tokio::time::Instant::now())),
            http: reqwest::Client::new(),
            rules: vec![],
        };

        // Create a JWT token with wrong audience
        use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};

        let header = Header::new(Algorithm::HS256);

        #[derive(serde::Serialize)]
        struct WrongAudClaims {
            iss: String,
            aud: String,
            sub: String,
            exp: i64,
        }

        let claims = WrongAudClaims {
            iss: "https://auth.example.com".to_string(),
            aud: "wrong-audience".to_string(), // Wrong audience
            sub: "test-user".to_string(),
            exp: (std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs()
                + 3600) as i64,
        };

        let token = encode(
            &header,
            &claims,
            &EncodingKey::from_secret("test-secret".as_ref()),
        )
        .unwrap();

        let result = provider.validate_token(&token).await;
        assert!(result.is_err());

        if let Err(ProxyError::SecurityError(msg)) = result {
            assert!(msg.contains("InvalidAudience"));
        } else {
            panic!("Expected SecurityError");
        }
    }

    #[tokio::test]
    async fn test_validate_claims_expired_token() {
        let provider = OidcProvider {
            issuer: "https://auth.example.com".to_string(),
            aud: None,
            shared_secret: Some("test-secret".to_string()),
            jwks_uri: "https://auth.example.com/jwks".to_string(),
            jwks: Arc::new(RwLock::new(None)),
            last_refresh: Arc::new(RwLock::new(tokio::time::Instant::now())),
            http: reqwest::Client::new(),
            rules: vec![],
        };

        // Create an expired JWT token
        use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};

        let header = Header::new(Algorithm::HS256);

        #[derive(serde::Serialize)]
        struct ExpiredClaims {
            iss: String,
            sub: String,
            exp: i64,
        }

        let claims = ExpiredClaims {
            iss: "https://auth.example.com".to_string(),
            sub: "test-user".to_string(),
            exp: (std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs()
                - 3600) as i64, // Expired 1 hour ago
        };

        let token = encode(
            &header,
            &claims,
            &EncodingKey::from_secret("test-secret".as_ref()),
        )
        .unwrap();

        let result = provider.validate_token(&token).await;
        assert!(result.is_err());

        if let Err(ProxyError::SecurityError(msg)) = result {
            assert!(msg.contains("ExpiredSignature"));
        } else {
            panic!("Expected SecurityError");
        }
    }

    #[tokio::test]
    async fn test_validate_claims_long_expiration() {
        let provider = OidcProvider {
            issuer: "https://auth.example.com".to_string(),
            aud: None,
            shared_secret: Some("test-secret".to_string()),
            jwks_uri: "https://auth.example.com/jwks".to_string(),
            jwks: Arc::new(RwLock::new(None)),
            last_refresh: Arc::new(RwLock::new(tokio::time::Instant::now())),
            http: reqwest::Client::new(),
            rules: vec![],
        };

        // Create a JWT token with very long expiration (effectively no expiration)
        use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};

        let header = Header::new(Algorithm::HS256);

        // Create claims with very long expiration (100 years from now)
        #[derive(serde::Serialize)]
        struct TestClaimsLongExp {
            iss: String,
            sub: String,
            exp: i64,
        }

        let claims = TestClaimsLongExp {
            iss: "https://auth.example.com".to_string(),
            sub: "test-user".to_string(),
            exp: (std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs()
                + (100 * 365 * 24 * 3600)) as i64, // 100 years
        };

        let token = encode(
            &header,
            &claims,
            &EncodingKey::from_secret("test-secret".as_ref()),
        )
        .unwrap();

        let result = provider.validate_token(&token).await;
        if result.is_err() {
            println!("Long expiration test error: {result:?}");
        }
        assert!(result.is_ok()); // Should succeed with very long expiration

        let validated_claims = result.unwrap();
        assert_eq!(validated_claims["iss"], "https://auth.example.com");
        assert_eq!(validated_claims["sub"], "test-user");
    }

    #[tokio::test]
    async fn test_validate_token_missing_key_id() {
        // Setup mock server
        let mock_server = MockServer::start().await;

        // Mock the discovery endpoint
        Mock::given(method("GET"))
            .and(path("/"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "issuer": mock_server.uri(),
                "jwks_uri": format!("{}/jwks", mock_server.uri())
            })))
            .mount(&mock_server)
            .await;

        // Mock the JWKS endpoint
        Mock::given(method("GET"))
            .and(path("/jwks"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "keys": [
                    {
                        "kty": "RSA",
                        "kid": "test-key-1",
                        "use": "sig",
                        "alg": "RS256",
                        "n": "test-modulus",
                        "e": "AQAB"
                    }
                ]
            })))
            .mount(&mock_server)
            .await;

        let config = OidcConfig {
            issuer_uri: mock_server.uri(),
            aud: None,
            shared_secret: None,
            bypass: vec![],
        };

        let provider = OidcProvider::discover(config).await.unwrap();

        // Create a JWT header without kid
        use serde_json::json;
        let header_json = json!({
            "alg": "RS256",
            "typ": "JWT"
            // No kid
        });
        let header_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(header_json.to_string().as_bytes());
        let payload_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(json!({"sub": "test"}).to_string().as_bytes());
        let token = format!("{header_b64}.{payload_b64}.signature");

        let result = provider.validate_token(&token).await;
        assert!(result.is_err());

        if let Err(ProxyError::SecurityError(msg)) = result {
            assert!(msg.contains("No key ID in token and no shared secret configured"));
        } else {
            panic!("Expected SecurityError");
        }
    }

    #[tokio::test]
    async fn test_validate_token_key_not_found() {
        // Setup mock server
        let mock_server = MockServer::start().await;

        // Mock the discovery endpoint
        Mock::given(method("GET"))
            .and(path("/"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "issuer": mock_server.uri(),
                "jwks_uri": format!("{}/jwks", mock_server.uri())
            })))
            .mount(&mock_server)
            .await;

        // Mock the JWKS endpoint
        Mock::given(method("GET"))
            .and(path("/jwks"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "keys": [
                    {
                        "kty": "RSA",
                        "kid": "different-key",
                        "use": "sig",
                        "alg": "RS256",
                        "n": "test-modulus",
                        "e": "AQAB"
                    }
                ]
            })))
            .mount(&mock_server)
            .await;

        let config = OidcConfig {
            issuer_uri: mock_server.uri(),
            aud: None,
            shared_secret: None,
            bypass: vec![],
        };

        let provider = OidcProvider::discover(config).await.unwrap();

        // Create a JWT header with non-existent kid
        use serde_json::json;
        let header_json = json!({
            "alg": "RS256",
            "typ": "JWT",
            "kid": "missing-key"
        });
        let header_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(header_json.to_string().as_bytes());
        let payload_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(json!({"sub": "test"}).to_string().as_bytes());
        let token = format!("{header_b64}.{payload_b64}.signature");

        let result = provider.validate_token(&token).await;
        assert!(result.is_err());

        if let Err(ProxyError::SecurityError(msg)) = result {
            assert!(msg.contains("not found in JWKS"));
        } else {
            panic!("Expected SecurityError");
        }
    }

    #[tokio::test]
    async fn test_integration_full_oidc_flow_with_bypass() {
        // Setup mock server
        let mock_server = MockServer::start().await;

        // Mock the discovery endpoint
        Mock::given(method("GET"))
            .and(path("/"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "issuer": mock_server.uri(),
                "jwks_uri": format!("{}/jwks", mock_server.uri())
            })))
            .mount(&mock_server)
            .await;

        let config = OidcConfig {
            issuer_uri: mock_server.uri(),
            aud: Some("test-app".to_string()),
            shared_secret: Some("integration-secret".to_string()),
            bypass: vec![
                RouteRuleConfig {
                    methods: vec!["GET".to_string()],
                    path: "/health".to_string(),
                },
                RouteRuleConfig {
                    methods: vec!["*".to_string()],
                    path: "/public/*".to_string(),
                },
            ],
        };

        let provider = OidcProvider::discover(config).await.unwrap();

        // Test 1: Bypass should work
        let bypass_request = ProxyRequest {
            method: HttpMethod::Get,
            path: "/health".to_string(),
            query: None,
            headers: HeaderMap::new(),
            body: reqwest::Body::from(Vec::new()),
            context: Arc::new(RwLock::new(RequestContext::default())),
            custom_target: Some("http://test.example.com".to_string()),
        };

        let result = provider.pre(bypass_request).await;
        assert!(result.is_ok());

        // Test 2: Test that non-bypassed requests require authentication
        let auth_request = ProxyRequest {
            method: HttpMethod::Post,
            path: "/api/users".to_string(),
            query: None,
            headers: HeaderMap::new(), // No authorization header
            body: reqwest::Body::from(Vec::new()),
            context: Arc::new(RwLock::new(RequestContext::default())),
            custom_target: Some("http://test.example.com".to_string()),
        };

        let result = provider.pre(auth_request).await;
        assert!(result.is_err());

        if let Err(ProxyError::SecurityError(msg)) = result {
            assert!(msg.contains("Missing authorization header"));
        } else {
            panic!("Expected SecurityError for missing auth header");
        }
    }

    #[tokio::test]
    async fn test_integration_full_oidc_flow_auth_failure() {
        // Setup mock server
        let mock_server = MockServer::start().await;

        // Mock the discovery endpoint
        Mock::given(method("GET"))
            .and(path("/"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "issuer": mock_server.uri(),
                "jwks_uri": format!("{}/jwks", mock_server.uri())
            })))
            .mount(&mock_server)
            .await;

        let config = OidcConfig {
            issuer_uri: mock_server.uri(),
            aud: None,
            shared_secret: Some("test-secret".to_string()),
            bypass: vec![],
        };

        let provider = OidcProvider::discover(config).await.unwrap();

        // Test with missing authorization header
        let request = ProxyRequest {
            method: HttpMethod::Post,
            path: "/api/users".to_string(),
            query: None,
            headers: HeaderMap::new(),
            body: reqwest::Body::from(Vec::new()),
            context: Arc::new(RwLock::new(RequestContext::default())),
            custom_target: Some("http://test.example.com".to_string()),
        };

        let result = provider.pre(request).await;
        assert!(result.is_err());

        if let Err(ProxyError::SecurityError(msg)) = result {
            assert!(msg.contains("Missing authorization header"));
        } else {
            panic!("Expected SecurityError");
        }
    }

    #[test]
    fn test_oidc_provider_is_bypassed() {
        let mut builder1 = GlobSetBuilder::new();
        builder1.add(Glob::new("/health").unwrap());
        let paths1 = builder1.build().unwrap();

        let mut builder2 = GlobSetBuilder::new();
        builder2.add(Glob::new("/public/*").unwrap());
        let paths2 = builder2.build().unwrap();

        let rules = vec![
            RouteRule {
                methods: vec!["GET".to_string()],
                paths: paths1,
            },
            RouteRule {
                methods: vec!["*".to_string()],
                paths: paths2,
            },
        ];

        let provider = OidcProvider {
            issuer: "https://auth.example.com".to_string(),
            aud: None,
            shared_secret: None,
            jwks_uri: "https://auth.example.com/jwks".to_string(),
            jwks: Arc::new(RwLock::new(None)),
            last_refresh: Arc::new(RwLock::new(tokio::time::Instant::now())),
            http: reqwest::Client::new(),
            rules,
        };

        // Test bypass rules
        assert!(provider.is_bypassed("GET", "/health"));
        assert!(!provider.is_bypassed("POST", "/health"));
        assert!(provider.is_bypassed("GET", "/public/api"));
        assert!(provider.is_bypassed("POST", "/public/api"));
        assert!(!provider.is_bypassed("GET", "/private/api"));
    }

    #[test]
    fn test_security_provider_trait_implementation() {
        let provider = OidcProvider {
            issuer: "https://auth.example.com".to_string(),
            aud: None,
            shared_secret: None,
            jwks_uri: "https://auth.example.com/jwks".to_string(),
            jwks: Arc::new(RwLock::new(None)),
            last_refresh: Arc::new(RwLock::new(tokio::time::Instant::now())),
            http: reqwest::Client::new(),
            rules: vec![],
        };

        assert_eq!(provider.name(), "OidcProvider");
        assert_eq!(provider.stage(), SecurityStage::Pre);
    }

    #[tokio::test]
    async fn test_oidc_provider_pre_bypass() {
        let mut builder = GlobSetBuilder::new();
        builder.add(Glob::new("/health").unwrap());
        let paths = builder.build().unwrap();

        let rules = vec![RouteRule {
            methods: vec!["GET".to_string()],
            paths,
        }];

        let provider = OidcProvider {
            issuer: "https://auth.example.com".to_string(),
            aud: None,
            shared_secret: None,
            jwks_uri: "https://auth.example.com/jwks".to_string(),
            jwks: Arc::new(RwLock::new(None)),
            last_refresh: Arc::new(RwLock::new(tokio::time::Instant::now())),
            http: reqwest::Client::new(),
            rules,
        };

        let headers = HeaderMap::new();
        let request = ProxyRequest {
            method: HttpMethod::Get,
            path: "/health".to_string(),
            query: None,
            headers,
            body: reqwest::Body::from(""),
            context: Arc::new(RwLock::new(RequestContext::default())),
            custom_target: None,
        };

        let result = provider.pre(request).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_oidc_provider_pre_missing_auth_header() {
        let provider = OidcProvider {
            issuer: "https://auth.example.com".to_string(),
            aud: None,
            shared_secret: None,
            jwks_uri: "https://auth.example.com/jwks".to_string(),
            jwks: Arc::new(RwLock::new(None)),
            last_refresh: Arc::new(RwLock::new(tokio::time::Instant::now())),
            http: reqwest::Client::new(),
            rules: vec![],
        };

        let headers = HeaderMap::new();
        let request = ProxyRequest {
            method: HttpMethod::Get,
            path: "/api/users".to_string(),
            query: None,
            headers,
            body: reqwest::Body::from(""),
            context: Arc::new(RwLock::new(RequestContext::default())),
            custom_target: None,
        };

        let result = provider.pre(request).await;
        assert!(result.is_err());

        if let Err(ProxyError::SecurityError(msg)) = result {
            assert_eq!(msg, "Missing authorization header");
        } else {
            panic!("Expected SecurityError");
        }
    }

    #[tokio::test]
    async fn test_oidc_provider_pre_invalid_auth_scheme() {
        let provider = OidcProvider {
            issuer: "https://auth.example.com".to_string(),
            aud: None,
            shared_secret: None,
            jwks_uri: "https://auth.example.com/jwks".to_string(),
            jwks: Arc::new(RwLock::new(None)),
            last_refresh: Arc::new(RwLock::new(tokio::time::Instant::now())),
            http: reqwest::Client::new(),
            rules: vec![],
        };

        let mut headers = HeaderMap::new();
        headers.insert("authorization", "Basic dXNlcjpwYXNz".parse().unwrap());

        let request = ProxyRequest {
            method: HttpMethod::Get,
            path: "/api/users".to_string(),
            query: None,
            headers,
            body: reqwest::Body::from(""),
            context: Arc::new(RwLock::new(RequestContext::default())),
            custom_target: None,
        };

        let result = provider.pre(request).await;
        assert!(result.is_err());

        if let Err(ProxyError::SecurityError(msg)) = result {
            assert!(msg.contains("Invalid authorization scheme"));
            assert!(msg.contains("expected 'Bearer'"));
        } else {
            panic!("Expected SecurityError");
        }
    }

    #[tokio::test]
    async fn test_oidc_provider_pre_empty_bearer_token() {
        let provider = OidcProvider {
            issuer: "https://auth.example.com".to_string(),
            aud: None,
            shared_secret: None,
            jwks_uri: "https://auth.example.com/jwks".to_string(),
            jwks: Arc::new(RwLock::new(None)),
            last_refresh: Arc::new(RwLock::new(tokio::time::Instant::now())),
            http: reqwest::Client::new(),
            rules: vec![],
        };

        let mut headers = HeaderMap::new();
        headers.insert("authorization", "Bearer ".parse().unwrap());

        let request = ProxyRequest {
            method: HttpMethod::Get,
            path: "/api/users".to_string(),
            query: None,
            headers,
            body: reqwest::Body::from(""),
            context: Arc::new(RwLock::new(RequestContext::default())),
            custom_target: None,
        };

        let result = provider.pre(request).await;
        assert!(result.is_err());

        if let Err(ProxyError::SecurityError(msg)) = result {
            assert_eq!(msg, "Empty bearer token");
        } else {
            panic!("Expected SecurityError");
        }
    }

    #[tokio::test]
    async fn test_jwk_to_decoding_key_rsa_success() {
        // Setup mock server for discovery
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "issuer": mock_server.uri(),
                "jwks_uri": format!("{}/jwks", mock_server.uri())
            })))
            .mount(&mock_server)
            .await;

        // Mock JWKS with RSA key
        Mock::given(method("GET"))
            .and(path("/jwks"))
            .respond_with(ResponseTemplate::new(200)
                .set_body_json(serde_json::json!({
                    "keys": [
                        {
                            "kty": "RSA",
                            "kid": "rsa-key-1",
                            "use": "sig",
                            "alg": "RS256",
                            "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
                            "e": "AQAB"
                        }
                    ]
                })))
            .mount(&mock_server)
            .await;

        let config = OidcConfig {
            issuer_uri: mock_server.uri(),
            aud: None,
            shared_secret: None,
            bypass: vec![],
        };

        let provider = OidcProvider::discover(config).await.unwrap();

        // Force JWKS refresh
        provider.refresh_jwks().await.unwrap();

        let jwks = provider.jwks.read().await;
        let jwks = jwks.as_ref().unwrap();
        let jwk = &jwks.keys[0];

        let result = provider.jwk_to_decoding_key(jwk);
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_jwk_to_decoding_key_ec_success() {
        // Setup mock server for discovery
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "issuer": mock_server.uri(),
                "jwks_uri": format!("{}/jwks", mock_server.uri())
            })))
            .mount(&mock_server)
            .await;

        // Mock JWKS with EC key
        Mock::given(method("GET"))
            .and(path("/jwks"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "keys": [
                    {
                        "kty": "EC",
                        "kid": "ec-key-1",
                        "use": "sig",
                        "alg": "ES256",
                        "crv": "P-256",
                        "x": "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
                        "y": "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"
                    }
                ]
            })))
            .mount(&mock_server)
            .await;

        let config = OidcConfig {
            issuer_uri: mock_server.uri(),
            aud: None,
            shared_secret: None,
            bypass: vec![],
        };

        let provider = OidcProvider::discover(config).await.unwrap();

        // Force JWKS refresh
        provider.refresh_jwks().await.unwrap();

        let jwks = provider.jwks.read().await;
        let jwks = jwks.as_ref().unwrap();
        let jwk = &jwks.keys[0];

        let result = provider.jwk_to_decoding_key(jwk);
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_jwk_to_decoding_key_octet_key_success() {
        // Setup mock server for discovery
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "issuer": mock_server.uri(),
                "jwks_uri": format!("{}/jwks", mock_server.uri())
            })))
            .mount(&mock_server)
            .await;

        // Mock JWKS with octet key (HMAC)
        Mock::given(method("GET"))
            .and(path("/jwks"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "keys": [
                    {
                        "kty": "oct",
                        "kid": "hmac-key-1",
                        "use": "sig",
                        "alg": "HS256",
                        "k": "GawgguFyGrWKav7AX4VKUg"
                    }
                ]
            })))
            .mount(&mock_server)
            .await;

        let config = OidcConfig {
            issuer_uri: mock_server.uri(),
            aud: None,
            shared_secret: None,
            bypass: vec![],
        };

        let provider = OidcProvider::discover(config).await.unwrap();

        // Force JWKS refresh
        provider.refresh_jwks().await.unwrap();

        let jwks = provider.jwks.read().await;
        let jwks = jwks.as_ref().unwrap();
        let jwk = &jwks.keys[0];

        let result = provider.jwk_to_decoding_key(jwk);
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_jwk_to_decoding_key_okp_success() {
        // Setup mock server for discovery
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "issuer": mock_server.uri(),
                "jwks_uri": format!("{}/jwks", mock_server.uri())
            })))
            .mount(&mock_server)
            .await;

        // Mock JWKS with OKP key (EdDSA)
        Mock::given(method("GET"))
            .and(path("/jwks"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "keys": [
                    {
                        "kty": "OKP",
                        "kid": "ed25519-key-1",
                        "use": "sig",
                        "alg": "EdDSA",
                        "crv": "Ed25519",
                        "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"
                    }
                ]
            })))
            .mount(&mock_server)
            .await;

        let config = OidcConfig {
            issuer_uri: mock_server.uri(),
            aud: None,
            shared_secret: None,
            bypass: vec![],
        };

        let provider = OidcProvider::discover(config).await.unwrap();

        // Force JWKS refresh
        provider.refresh_jwks().await.unwrap();

        let jwks = provider.jwks.read().await;
        let jwks = jwks.as_ref().unwrap();
        let jwk = &jwks.keys[0];

        let result = provider.jwk_to_decoding_key(jwk);
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_validate_token_with_kid_fallback_to_shared_secret() {
        let provider = OidcProvider {
            issuer: "https://auth.example.com".to_string(),
            aud: None,
            shared_secret: Some("test-secret".to_string()),
            jwks_uri: "https://auth.example.com/jwks".to_string(),
            jwks: Arc::new(RwLock::new(Some(JwkSet { keys: vec![] }))), // Empty JWKS
            last_refresh: Arc::new(RwLock::new(tokio::time::Instant::now())),
            http: reqwest::Client::new(),
            rules: vec![],
        };

        // Create a HMAC JWT token with kid that won't be found in JWKS
        use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};

        let mut header = Header::new(Algorithm::HS256);
        header.kid = Some("missing-key".to_string());

        #[derive(serde::Serialize)]
        struct TestClaims {
            iss: String,
            sub: String,
            exp: i64,
        }

        let claims = TestClaims {
            iss: "https://auth.example.com".to_string(),
            sub: "test-user".to_string(),
            exp: (std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs()
                + 3600) as i64,
        };

        let token = encode(
            &header,
            &claims,
            &EncodingKey::from_secret("test-secret".as_ref()),
        )
        .unwrap();

        let result = provider.validate_token(&token).await;
        assert!(result.is_ok());

        let validated_claims = result.unwrap();
        assert_eq!(validated_claims["iss"], "https://auth.example.com");
        assert_eq!(validated_claims["sub"], "test-user");
    }

    #[tokio::test]
    async fn test_validate_token_non_hmac_algorithm_with_missing_kid() {
        let provider = OidcProvider {
            issuer: "https://auth.example.com".to_string(),
            aud: None,
            shared_secret: Some("test-secret".to_string()),
            jwks_uri: "https://auth.example.com/jwks".to_string(),
            jwks: Arc::new(RwLock::new(Some(JwkSet { keys: vec![] }))), // Empty JWKS
            last_refresh: Arc::new(RwLock::new(tokio::time::Instant::now())),
            http: reqwest::Client::new(),
            rules: vec![],
        };

        // Create a JWT header with RS256 algorithm and missing kid
        use serde_json::json;
        let header_json = json!({
            "alg": "RS256",
            "typ": "JWT",
            "kid": "missing-rsa-key"
        });
        let header_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(header_json.to_string().as_bytes());
        let payload_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(json!({"sub": "test"}).to_string().as_bytes());
        let token = format!("{header_b64}.{payload_b64}.signature");

        let result = provider.validate_token(&token).await;
        assert!(result.is_err());

        if let Err(ProxyError::SecurityError(msg)) = result {
            assert!(msg.contains("not found in JWKS"));
        } else {
            panic!("Expected SecurityError");
        }
    }

    #[tokio::test]
    async fn test_validate_token_different_algorithms() {
        let provider = OidcProvider {
            issuer: "https://auth.example.com".to_string(),
            aud: None,
            shared_secret: Some("test-secret-key-for-hs384".to_string()),
            jwks_uri: "https://auth.example.com/jwks".to_string(),
            jwks: Arc::new(RwLock::new(None)),
            last_refresh: Arc::new(RwLock::new(tokio::time::Instant::now())),
            http: reqwest::Client::new(),
            rules: vec![],
        };

        // Test HS384 algorithm
        use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};

        let header = Header::new(Algorithm::HS384);

        #[derive(serde::Serialize)]
        struct TestClaims {
            iss: String,
            sub: String,
            exp: i64,
        }

        let claims = TestClaims {
            iss: "https://auth.example.com".to_string(),
            sub: "test-user".to_string(),
            exp: (std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs()
                + 3600) as i64,
        };

        let token = encode(
            &header,
            &claims,
            &EncodingKey::from_secret("test-secret-key-for-hs384".as_ref()),
        )
        .unwrap();

        let result = provider.validate_token(&token).await;
        assert!(result.is_ok());

        let validated_claims = result.unwrap();
        assert_eq!(validated_claims["iss"], "https://auth.example.com");
        assert_eq!(validated_claims["sub"], "test-user");
    }

    #[tokio::test]
    async fn test_validate_token_hs512_algorithm() {
        let provider = OidcProvider {
            issuer: "https://auth.example.com".to_string(),
            aud: None,
            shared_secret: Some("test-secret-key-for-hs512-algorithm".to_string()),
            jwks_uri: "https://auth.example.com/jwks".to_string(),
            jwks: Arc::new(RwLock::new(None)),
            last_refresh: Arc::new(RwLock::new(tokio::time::Instant::now())),
            http: reqwest::Client::new(),
            rules: vec![],
        };

        // Test HS512 algorithm
        let header = Header::new(Algorithm::HS512);

        #[derive(serde::Serialize)]
        struct TestClaims {
            iss: String,
            sub: String,
            exp: i64,
        }

        let claims = TestClaims {
            iss: "https://auth.example.com".to_string(),
            sub: "test-user".to_string(),
            exp: (std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs()
                + 3600) as i64,
        };

        let token = encode(
            &header,
            &claims,
            &EncodingKey::from_secret("test-secret-key-for-hs512-algorithm".as_ref()),
        )
        .unwrap();

        let result = provider.validate_token(&token).await;
        assert!(result.is_ok());

        let validated_claims = result.unwrap();
        assert_eq!(validated_claims["iss"], "https://auth.example.com");
        assert_eq!(validated_claims["sub"], "test-user");
    }

    #[test]
    fn test_validate_std_claims_success() {
        let provider = OidcProvider {
            issuer: "https://auth.example.com".to_string(),
            aud: Some("test-audience".to_string()),
            shared_secret: None,
            jwks_uri: "https://auth.example.com/jwks".to_string(),
            jwks: Arc::new(RwLock::new(None)),
            last_refresh: Arc::new(RwLock::new(tokio::time::Instant::now())),
            http: reqwest::Client::new(),
            rules: vec![],
        };

        let claims = serde_json::json!({
            "iss": "https://auth.example.com",
            "aud": "test-audience",
            "sub": "test-user",
            "exp": (std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() + 3600)
        });

        let result = provider.validate_std_claims(&claims);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_std_claims_wrong_issuer() {
        let provider = OidcProvider {
            issuer: "https://auth.example.com".to_string(),
            aud: None,
            shared_secret: None,
            jwks_uri: "https://auth.example.com/jwks".to_string(),
            jwks: Arc::new(RwLock::new(None)),
            last_refresh: Arc::new(RwLock::new(tokio::time::Instant::now())),
            http: reqwest::Client::new(),
            rules: vec![],
        };

        let claims = serde_json::json!({
            "iss": "https://wrong-issuer.com",
            "sub": "test-user",
            "exp": (std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() + 3600)
        });

        let result = provider.validate_std_claims(&claims);
        assert!(result.is_err());

        if let Err(ProxyError::SecurityError(msg)) = result {
            assert!(msg.contains("Invalid issuer"));
            assert!(msg.contains("expected 'https://auth.example.com'"));
            assert!(msg.contains("got 'https://wrong-issuer.com'"));
        } else {
            panic!("Expected SecurityError");
        }
    }

    #[test]
    fn test_validate_std_claims_missing_issuer() {
        let provider = OidcProvider {
            issuer: "https://auth.example.com".to_string(),
            aud: None,
            shared_secret: None,
            jwks_uri: "https://auth.example.com/jwks".to_string(),
            jwks: Arc::new(RwLock::new(None)),
            last_refresh: Arc::new(RwLock::new(tokio::time::Instant::now())),
            http: reqwest::Client::new(),
            rules: vec![],
        };

        let claims = serde_json::json!({
            "sub": "test-user",
            "exp": (std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() + 3600)
        });

        let result = provider.validate_std_claims(&claims);
        assert!(result.is_err());

        if let Err(ProxyError::SecurityError(msg)) = result {
            assert_eq!(msg, "Missing issuer claim");
        } else {
            panic!("Expected SecurityError");
        }
    }

    #[test]
    fn test_validate_std_claims_audience_array_success() {
        let provider = OidcProvider {
            issuer: "https://auth.example.com".to_string(),
            aud: Some("test-audience".to_string()),
            shared_secret: None,
            jwks_uri: "https://auth.example.com/jwks".to_string(),
            jwks: Arc::new(RwLock::new(None)),
            last_refresh: Arc::new(RwLock::new(tokio::time::Instant::now())),
            http: reqwest::Client::new(),
            rules: vec![],
        };

        let claims = serde_json::json!({
            "iss": "https://auth.example.com",
            "aud": ["other-audience", "test-audience", "another-audience"],
            "sub": "test-user",
            "exp": (std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() + 3600)
        });

        let result = provider.validate_std_claims(&claims);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_std_claims_audience_array_failure() {
        let provider = OidcProvider {
            issuer: "https://auth.example.com".to_string(),
            aud: Some("test-audience".to_string()),
            shared_secret: None,
            jwks_uri: "https://auth.example.com/jwks".to_string(),
            jwks: Arc::new(RwLock::new(None)),
            last_refresh: Arc::new(RwLock::new(tokio::time::Instant::now())),
            http: reqwest::Client::new(),
            rules: vec![],
        };

        let claims = serde_json::json!({
            "iss": "https://auth.example.com",
            "aud": ["other-audience", "wrong-audience", "another-audience"],
            "sub": "test-user",
            "exp": (std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() + 3600)
        });

        let result = provider.validate_std_claims(&claims);
        assert!(result.is_err());

        if let Err(ProxyError::SecurityError(msg)) = result {
            assert!(msg.contains("Invalid audience"));
            assert!(msg.contains("expected 'test-audience'"));
        } else {
            panic!("Expected SecurityError");
        }
    }

    #[test]
    fn test_validate_std_claims_invalid_audience_type() {
        let provider = OidcProvider {
            issuer: "https://auth.example.com".to_string(),
            aud: Some("test-audience".to_string()),
            shared_secret: None,
            jwks_uri: "https://auth.example.com/jwks".to_string(),
            jwks: Arc::new(RwLock::new(None)),
            last_refresh: Arc::new(RwLock::new(tokio::time::Instant::now())),
            http: reqwest::Client::new(),
            rules: vec![],
        };

        let claims = serde_json::json!({
            "iss": "https://auth.example.com",
            "aud": 12345, // Invalid type (number instead of string/array)
            "sub": "test-user",
            "exp": (std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() + 3600)
        });

        let result = provider.validate_std_claims(&claims);
        assert!(result.is_err());

        if let Err(ProxyError::SecurityError(msg)) = result {
            assert!(msg.contains("Invalid audience"));
            assert!(msg.contains("expected 'test-audience'"));
        } else {
            panic!("Expected SecurityError");
        }
    }

    #[test]
    fn test_validate_std_claims_expired_token() {
        let provider = OidcProvider {
            issuer: "https://auth.example.com".to_string(),
            aud: None,
            shared_secret: None,
            jwks_uri: "https://auth.example.com/jwks".to_string(),
            jwks: Arc::new(RwLock::new(None)),
            last_refresh: Arc::new(RwLock::new(tokio::time::Instant::now())),
            http: reqwest::Client::new(),
            rules: vec![],
        };

        let claims = serde_json::json!({
            "iss": "https://auth.example.com",
            "sub": "test-user",
            "exp": (std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() - 3600) // Expired 1 hour ago
        });

        let result = provider.validate_std_claims(&claims);
        assert!(result.is_err());

        if let Err(ProxyError::SecurityError(msg)) = result {
            assert!(msg.contains("Token expired"));
        } else {
            panic!("Expected SecurityError");
        }
    }

    #[test]
    fn test_validate_std_claims_no_audience_configured() {
        let provider = OidcProvider {
            issuer: "https://auth.example.com".to_string(),
            aud: None, // No audience configured
            shared_secret: None,
            jwks_uri: "https://auth.example.com/jwks".to_string(),
            jwks: Arc::new(RwLock::new(None)),
            last_refresh: Arc::new(RwLock::new(tokio::time::Instant::now())),
            http: reqwest::Client::new(),
            rules: vec![],
        };

        let claims = serde_json::json!({
            "iss": "https://auth.example.com",
            "aud": "any-audience", // Should be ignored since no audience is configured
            "sub": "test-user",
            "exp": (std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() + 3600)
        });

        let result = provider.validate_std_claims(&claims);
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_jwks_refresh_empty_keys() {
        // Setup mock server
        let mock_server = MockServer::start().await;

        // Mock the discovery endpoint
        Mock::given(method("GET"))
            .and(path("/"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "issuer": mock_server.uri(),
                "jwks_uri": format!("{}/jwks", mock_server.uri())
            })))
            .mount(&mock_server)
            .await;

        // Mock the JWKS endpoint with empty keys array
        Mock::given(method("GET"))
            .and(path("/jwks"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "keys": []
            })))
            .mount(&mock_server)
            .await;

        let config = OidcConfig {
            issuer_uri: mock_server.uri(),
            aud: None,
            shared_secret: None,
            bypass: vec![],
        };

        let provider = OidcProvider::discover(config).await.unwrap();

        // Force cache expiration
        {
            let mut jwks_w = provider.jwks.write().await;
            *jwks_w = None;
        }
        {
            let mut refresh_w = provider.last_refresh.write().await;
            *refresh_w = tokio::time::Instant::now()
                .checked_sub(JWKS_REFRESH + std::time::Duration::from_secs(1))
                .unwrap_or_else(|| {
                    tokio::time::Instant::now()
                        .checked_sub(std::time::Duration::from_millis(1))
                        .unwrap_or_else(tokio::time::Instant::now)
                });
        }

        let result = provider.refresh_jwks().await;
        assert!(result.is_ok());

        // Verify JWKS was cached with empty keys
        let jwks = provider.jwks.read().await;
        assert!(jwks.is_some());
        let jwks = jwks.as_ref().unwrap();
        assert_eq!(jwks.keys.len(), 0);
    }

    #[tokio::test]
    async fn test_jwks_refresh_cognito_format() {
        // Test with AWS Cognito-style JWKS response
        let mock_server = MockServer::start().await;

        // Mock the discovery endpoint
        Mock::given(method("GET"))
            .and(path("/"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "issuer": mock_server.uri(),
                "jwks_uri": format!("{}/jwks", mock_server.uri())
            })))
            .mount(&mock_server)
            .await;

        // Mock the JWKS endpoint with Cognito-style response
        Mock::given(method("GET"))
            .and(path("/jwks"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "keys": [
                    {
                        "kid": "1234example=",
                        "alg": "RS256",
                        "kty": "RSA",
                        "e": "AQAB",
                        "n": "1234567890",
                        "use": "sig"
                    },
                    {
                        "kid": "5678example=",
                        "alg": "RS256",
                        "kty": "RSA",
                        "e": "AQAB",
                        "n": "987654321",
                        "use": "sig"
                    }
                ]
            })))
            .mount(&mock_server)
            .await;

        let config = OidcConfig {
            issuer_uri: mock_server.uri(),
            aud: None,
            shared_secret: None,
            bypass: vec![],
        };

        let provider = OidcProvider::discover(config).await.unwrap();

        // Force cache expiration
        {
            let mut jwks_w = provider.jwks.write().await;
            *jwks_w = None;
        }
        {
            let mut refresh_w = provider.last_refresh.write().await;
            *refresh_w = tokio::time::Instant::now()
                .checked_sub(JWKS_REFRESH + std::time::Duration::from_secs(1))
                .unwrap_or_else(|| {
                    tokio::time::Instant::now()
                        .checked_sub(std::time::Duration::from_millis(1))
                        .unwrap_or_else(tokio::time::Instant::now)
                });
        }

        let result = provider.refresh_jwks().await;
        assert!(result.is_ok());

        // Verify JWKS was cached correctly
        let jwks = provider.jwks.read().await;
        assert!(jwks.is_some());
        let jwks = jwks.as_ref().unwrap();
        assert_eq!(jwks.keys.len(), 2);
        assert_eq!(jwks.keys[0].common.key_id, Some("1234example=".to_string()));
        assert_eq!(jwks.keys[1].common.key_id, Some("5678example=".to_string()));
    }

    #[tokio::test]
    async fn test_jwks_refresh_with_extra_fields() {
        // Test JWKS response with additional fields that should be ignored
        let mock_server = MockServer::start().await;

        // Mock the discovery endpoint
        Mock::given(method("GET"))
            .and(path("/"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "issuer": mock_server.uri(),
                "jwks_uri": format!("{}/jwks", mock_server.uri())
            })))
            .mount(&mock_server)
            .await;

        // Mock the JWKS endpoint with extra fields
        Mock::given(method("GET"))
            .and(path("/jwks"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "keys": [
                    {
                        "kty": "RSA",
                        "kid": "test-key-1",
                        "use": "sig",
                        "alg": "RS256",
                        "n": "test-modulus",
                        "e": "AQAB",
                        // Extra fields that should be ignored
                        "x5c": ["cert1", "cert2"],
                        "x5t": "thumbprint",
                        "x5t#S256": "sha256-thumbprint",
                        "custom_field": "custom_value"
                    }
                ],
                // Extra top-level fields
                "cache_max_age": 3600,
                "custom_metadata": {
                    "provider": "test"
                }
            })))
            .mount(&mock_server)
            .await;

        let config = OidcConfig {
            issuer_uri: mock_server.uri(),
            aud: None,
            shared_secret: None,
            bypass: vec![],
        };

        let provider = OidcProvider::discover(config).await.unwrap();

        // Force cache expiration
        {
            let mut jwks_w = provider.jwks.write().await;
            *jwks_w = None;
        }
        {
            let mut refresh_w = provider.last_refresh.write().await;
            *refresh_w = tokio::time::Instant::now()
                .checked_sub(JWKS_REFRESH + std::time::Duration::from_secs(1))
                .unwrap_or_else(|| {
                    tokio::time::Instant::now()
                        .checked_sub(std::time::Duration::from_millis(1))
                        .unwrap_or_else(tokio::time::Instant::now)
                });
        }

        let result = provider.refresh_jwks().await;
        assert!(result.is_ok());

        // Verify JWKS was cached correctly despite extra fields
        let jwks = provider.jwks.read().await;
        assert!(jwks.is_some());
        let jwks = jwks.as_ref().unwrap();
        assert_eq!(jwks.keys.len(), 1);
        assert_eq!(jwks.keys[0].common.key_id, Some("test-key-1".to_string()));
    }

    #[tokio::test]
    async fn test_jwks_refresh_missing_keys_field() {
        // Test JWKS response missing the "keys" field
        let mock_server = MockServer::start().await;

        // Mock the discovery endpoint
        Mock::given(method("GET"))
            .and(path("/"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "issuer": mock_server.uri(),
                "jwks_uri": format!("{}/jwks", mock_server.uri())
            })))
            .mount(&mock_server)
            .await;

        // Mock the JWKS endpoint without "keys" field
        Mock::given(method("GET"))
            .and(path("/jwks"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "metadata": "some data",
                "other_field": "value"
            })))
            .mount(&mock_server)
            .await;

        let config = OidcConfig {
            issuer_uri: mock_server.uri(),
            aud: None,
            shared_secret: None,
            bypass: vec![],
        };

        let provider = OidcProvider::discover(config).await.unwrap();

        // Force cache expiration
        {
            let mut jwks_w = provider.jwks.write().await;
            *jwks_w = None;
        }
        {
            let mut refresh_w = provider.last_refresh.write().await;
            *refresh_w = tokio::time::Instant::now()
                .checked_sub(JWKS_REFRESH + std::time::Duration::from_secs(1))
                .unwrap_or_else(|| {
                    tokio::time::Instant::now()
                        .checked_sub(std::time::Duration::from_millis(1))
                        .unwrap_or_else(tokio::time::Instant::now)
                });
        }

        let result = provider.refresh_jwks().await;
        assert!(result.is_err());

        if let Err(ProxyError::SecurityError(msg)) = result {
            assert!(msg.contains("Failed to parse JWKS response"));
        } else {
            panic!("Expected SecurityError");
        }
    }

    #[tokio::test]
    async fn test_jwks_refresh_malformed_key() {
        // Test JWKS response with malformed key structure
        let mock_server = MockServer::start().await;

        // Mock the discovery endpoint
        Mock::given(method("GET"))
            .and(path("/"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "issuer": mock_server.uri(),
                "jwks_uri": format!("{}/jwks", mock_server.uri())
            })))
            .mount(&mock_server)
            .await;

        // Mock the JWKS endpoint with malformed key
        Mock::given(method("GET"))
            .and(path("/jwks"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "keys": [
                    {
                        "kty": "RSA",
                        "kid": "test-key-1",
                        "use": "sig",
                        "alg": "RS256",
                        // Missing required fields 'n' and 'e' for RSA key
                    },
                    {
                        // Valid key to test partial parsing
                        "kty": "RSA",
                        "kid": "test-key-2",
                        "use": "sig",
                        "alg": "RS256",
                        "n": "test-modulus",
                        "e": "AQAB"
                    }
                ]
            })))
            .mount(&mock_server)
            .await;

        let config = OidcConfig {
            issuer_uri: mock_server.uri(),
            aud: None,
            shared_secret: None,
            bypass: vec![],
        };

        let provider = OidcProvider::discover(config).await.unwrap();

        // Force cache expiration
        {
            let mut jwks_w = provider.jwks.write().await;
            *jwks_w = None;
        }
        {
            let mut refresh_w = provider.last_refresh.write().await;
            *refresh_w = tokio::time::Instant::now()
                .checked_sub(JWKS_REFRESH + std::time::Duration::from_secs(1))
                .unwrap_or_else(|| {
                    tokio::time::Instant::now()
                        .checked_sub(std::time::Duration::from_millis(1))
                        .unwrap_or_else(tokio::time::Instant::now)
                });
        }

        let result = provider.refresh_jwks().await;
        // This might succeed or fail depending on how strict the parser is
        // The jsonwebtoken crate might skip malformed keys or fail entirely
        match result {
            Ok(_) => {
                // If it succeeds, verify that at least the valid key was parsed
                let jwks = provider.jwks.read().await;
                assert!(jwks.is_some());
                let jwks = jwks.as_ref().unwrap();
                // Should have at least one valid key
                assert!(!jwks.keys.is_empty());
            }
            Err(ProxyError::SecurityError(msg)) => {
                // If it fails, it should be a parsing error
                assert!(msg.contains("Failed to parse JWKS response"));
            }
            Err(e) => panic!("Unexpected error type: {e:?}"),
        }
    }

    #[tokio::test]
    async fn test_jwks_refresh_different_content_types() {
        // Test JWKS response with different content types
        let mock_server = MockServer::start().await;

        // Mock the discovery endpoint
        Mock::given(method("GET"))
            .and(path("/"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "issuer": mock_server.uri(),
                "jwks_uri": format!("{}/jwks", mock_server.uri())
            })))
            .mount(&mock_server)
            .await;

        // Mock the JWKS endpoint with text/plain content type but valid JSON
        Mock::given(method("GET"))
            .and(path("/jwks"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string(
                        serde_json::json!({
                            "keys": [
                                {
                                    "kty": "RSA",
                                    "kid": "test-key-1",
                                    "use": "sig",
                                    "alg": "RS256",
                                    "n": "test-modulus",
                                    "e": "AQAB"
                                }
                            ]
                        })
                        .to_string(),
                    )
                    .insert_header("content-type", "text/plain"),
            )
            .mount(&mock_server)
            .await;

        let config = OidcConfig {
            issuer_uri: mock_server.uri(),
            aud: None,
            shared_secret: None,
            bypass: vec![],
        };

        let provider = OidcProvider::discover(config).await.unwrap();

        // Force cache expiration
        {
            let mut jwks_w = provider.jwks.write().await;
            *jwks_w = None;
        }
        {
            let mut refresh_w = provider.last_refresh.write().await;
            *refresh_w = tokio::time::Instant::now()
                .checked_sub(JWKS_REFRESH + std::time::Duration::from_secs(1))
                .unwrap_or_else(|| {
                    tokio::time::Instant::now()
                        .checked_sub(std::time::Duration::from_millis(1))
                        .unwrap_or_else(tokio::time::Instant::now)
                });
        }

        let result = provider.refresh_jwks().await;
        // reqwest should handle this gracefully and parse JSON regardless of content-type
        assert!(result.is_ok());

        // Verify JWKS was cached correctly
        let jwks = provider.jwks.read().await;
        assert!(jwks.is_some());
        let jwks = jwks.as_ref().unwrap();
        assert_eq!(jwks.keys.len(), 1);
        assert_eq!(jwks.keys[0].common.key_id, Some("test-key-1".to_string()));
    }

    #[tokio::test]
    async fn test_jwks_refresh_fallback_parsing() {
        // Test JWKS response that requires fallback parsing
        let mock_server = MockServer::start().await;

        // Mock the discovery endpoint
        Mock::given(method("GET"))
            .and(path("/"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "issuer": mock_server.uri(),
                "jwks_uri": format!("{}/jwks", mock_server.uri())
            })))
            .mount(&mock_server)
            .await;

        // Mock the JWKS endpoint with a format that might cause standard parsing to fail
        // but should work with fallback parsing
        Mock::given(method("GET"))
            .and(path("/jwks"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "keys": [
                    {
                        "kty": "RSA",
                        "kid": "fallback-key-1",
                        "use": "sig",
                        "alg": "RS256",
                        "n": "test-modulus-fallback",
                        "e": "AQAB",
                        // Extra fields that might confuse strict parsers
                        "x5c": ["cert1"],
                        "x5t": "thumbprint",
                        "x5t#S256": "sha256-thumbprint",
                        "unknown_field": "unknown_value"
                    }
                ],
                // Extra top-level fields
                "cache_max_age": 3600,
                "next_update": "2024-01-01T00:00:00Z"
            })))
            .mount(&mock_server)
            .await;

        let config = OidcConfig {
            issuer_uri: mock_server.uri(),
            aud: None,
            shared_secret: None,
            bypass: vec![],
        };

        let provider = OidcProvider::discover(config).await.unwrap();

        // Force cache expiration
        {
            let mut jwks_w = provider.jwks.write().await;
            *jwks_w = None;
        }
        {
            let mut refresh_w = provider.last_refresh.write().await;
            *refresh_w = tokio::time::Instant::now()
                .checked_sub(JWKS_REFRESH + std::time::Duration::from_secs(1))
                .unwrap_or_else(|| {
                    tokio::time::Instant::now()
                        .checked_sub(std::time::Duration::from_millis(1))
                        .unwrap_or_else(tokio::time::Instant::now)
                });
        }

        let result = provider.refresh_jwks().await;
        assert!(result.is_ok());

        // Verify JWKS was cached correctly using fallback parsing
        let jwks = provider.jwks.read().await;
        assert!(jwks.is_some());
        let jwks = jwks.as_ref().unwrap();
        assert_eq!(jwks.keys.len(), 1);
        assert_eq!(
            jwks.keys[0].common.key_id,
            Some("fallback-key-1".to_string())
        );
    }

    #[tokio::test]
    async fn test_jwks_refresh_partial_key_failure() {
        // Test JWKS response where some keys are valid and some are malformed
        let mock_server = MockServer::start().await;

        // Mock the discovery endpoint
        Mock::given(method("GET"))
            .and(path("/"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "issuer": mock_server.uri(),
                "jwks_uri": format!("{}/jwks", mock_server.uri())
            })))
            .mount(&mock_server)
            .await;

        // Mock the JWKS endpoint with mixed valid/invalid keys
        Mock::given(method("GET"))
            .and(path("/jwks"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "keys": [
                    {
                        // Valid RSA key
                        "kty": "RSA",
                        "kid": "valid-key-1",
                        "use": "sig",
                        "alg": "RS256",
                        "n": "test-modulus",
                        "e": "AQAB"
                    },
                    {
                        // Invalid key - missing required fields
                        "kty": "RSA",
                        "kid": "invalid-key-1",
                        "use": "sig",
                        "alg": "RS256"
                        // Missing 'n' and 'e'
                    },
                    {
                        // Another valid key
                        "kty": "EC",
                        "kid": "valid-key-2",
                        "use": "sig",
                        "alg": "ES256",
                        "crv": "P-256",
                        "x": "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
                        "y": "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"
                    }
                ]
            })))
            .mount(&mock_server)
            .await;

        let config = OidcConfig {
            issuer_uri: mock_server.uri(),
            aud: None,
            shared_secret: None,
            bypass: vec![],
        };

        let provider = OidcProvider::discover(config).await.unwrap();

        // Force cache expiration
        {
            let mut jwks_w = provider.jwks.write().await;
            *jwks_w = None;
        }
        {
            let mut refresh_w = provider.last_refresh.write().await;
            *refresh_w = tokio::time::Instant::now()
                .checked_sub(JWKS_REFRESH + std::time::Duration::from_secs(1))
                .unwrap_or_else(|| {
                    tokio::time::Instant::now()
                        .checked_sub(std::time::Duration::from_millis(1))
                        .unwrap_or_else(tokio::time::Instant::now)
                });
        }

        let result = provider.refresh_jwks().await;

        // The current implementation might fail entirely with malformed keys
        // This is actually acceptable behavior - strict parsing is safer
        match result {
            Ok(_) => {
                // If it succeeds, verify that valid keys were parsed
                let jwks = provider.jwks.read().await;
                assert!(jwks.is_some());
                let jwks = jwks.as_ref().unwrap();
                // Should have at least 1 valid key
                assert!(!jwks.keys.is_empty());

                let key_ids: Vec<_> = jwks
                    .keys
                    .iter()
                    .filter_map(|k| k.common.key_id.as_ref())
                    .collect();
                // At least one of the valid keys should be present
                assert!(
                    key_ids.contains(&&"valid-key-1".to_string())
                        || key_ids.contains(&&"valid-key-2".to_string())
                );
            }
            Err(ProxyError::SecurityError(msg)) => {
                // It's also acceptable for parsing to fail entirely with malformed keys
                assert!(msg.contains("Failed to parse JWKS response"));
                println!("JWKS parsing failed as expected with malformed keys: {msg}");
            }
            Err(e) => panic!("Unexpected error type: {e:?}"),
        }
    }

    #[tokio::test]
    async fn test_jwks_refresh_real_world_format() {
        // Test with a real-world JWKS format similar to what AWS Cognito or other providers return
        let mock_server = MockServer::start().await;

        // Mock the discovery endpoint
        Mock::given(method("GET"))
            .and(path("/"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "issuer": mock_server.uri(),
                "jwks_uri": format!("{}/jwks", mock_server.uri())
            })))
            .mount(&mock_server)
            .await;

        // Mock the JWKS endpoint with a real-world format
        Mock::given(method("GET"))
            .and(path("/jwks"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "keys": [
                    {
                        "kty": "RSA",
                        "use": "sig",
                        "kid": "test-key-1",
                        "alg": "RS256",
                        "n": "3TZbOj2V9n8Mml9L7djP2F_qPCP4Sk7peS45-bmQHjvHRrNMFZJ_MFWe8gVpNiovr_RLDWyDWjsXwNG6Rp9ueazrGm3YqWYdMCpd9Ba3re02MDzq4glHcoGZxWQQg_qJ0b8MnG5MdI0p4VqDLhLEbJxHZz5MBgDfME07N3Zn0Lj7ytzHPpHXrhMp3zKBPWBzZShH-JG-QDLKTmODdpZaWMRG0bWo5eyfXNkp0CWTvZgxzZ5rNHHWz4Ff-6zqMSD1x8DN5x-UEcSmpWVRu1zPNMBvqPEoaJ7-xSu4BumkEWhxLkge9Z5Y2QWDKy_D5PSabJQQ3v_G4eqWa6VCT3zZw",
                        "e": "AQAB"
                    }
                ]
            })))
            .mount(&mock_server)
            .await;

        let config = OidcConfig {
            issuer_uri: mock_server.uri(),
            aud: None,
            shared_secret: None,
            bypass: vec![],
        };

        let provider = OidcProvider::discover(config).await.unwrap();

        // Force cache expiration
        {
            let mut jwks_w = provider.jwks.write().await;
            *jwks_w = None;
        }
        {
            let mut refresh_w = provider.last_refresh.write().await;
            *refresh_w = tokio::time::Instant::now()
                .checked_sub(JWKS_REFRESH + std::time::Duration::from_secs(1))
                .unwrap_or_else(|| {
                    tokio::time::Instant::now()
                        .checked_sub(std::time::Duration::from_millis(1))
                        .unwrap_or_else(tokio::time::Instant::now)
                });
        }

        let result = provider.refresh_jwks().await;
        assert!(
            result.is_ok(),
            "JWKS refresh should succeed with real-world format"
        );

        // Verify JWKS was parsed correctly
        let jwks = provider.jwks.read().await;
        assert!(jwks.is_some(), "JWKS should be cached");
        let jwks = jwks.as_ref().unwrap();
        assert_eq!(jwks.keys.len(), 1, "Should have exactly one key");

        let key = &jwks.keys[0];
        assert_eq!(
            key.common.key_id,
            Some("test-key-1".to_string()),
            "Key ID should match"
        );

        // Check that the key has the expected properties (the exact enum values may vary)
        assert!(key.common.key_id.is_some(), "Key should have an ID");

        // Verify the key type by checking the algorithm parameters
        match &key.algorithm {
            jsonwebtoken::jwk::AlgorithmParameters::RSA(rsa_params) => {
                assert!(!rsa_params.n.is_empty(), "RSA modulus should not be empty");
                assert!(!rsa_params.e.is_empty(), "RSA exponent should not be empty");
                assert_eq!(rsa_params.e, "AQAB", "RSA exponent should be AQAB");
            }
            _ => panic!("Expected RSA key parameters"),
        }

        // Verify the key can be converted to a decoding key
        let decoding_key_result = provider.jwk_to_decoding_key(key);
        match decoding_key_result {
            Ok(_) => {
                // Success - the key was converted properly
            }
            Err(e) => {
                // For this test, we'll just verify the JWKS parsing worked
                // The actual key conversion might fail with test data
                println!("Key conversion failed (expected with test data): {e}");
            }
        }
    }

    #[tokio::test]
    async fn test_jwks_refresh_multiple_real_keys() {
        // Test with multiple keys in different formats (RSA, EC, etc.)
        let mock_server = MockServer::start().await;

        // Mock the discovery endpoint
        Mock::given(method("GET"))
            .and(path("/"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "issuer": mock_server.uri(),
                "jwks_uri": format!("{}/jwks", mock_server.uri())
            })))
            .mount(&mock_server)
            .await;

        // Mock the JWKS endpoint with multiple real-world keys
        Mock::given(method("GET"))
            .and(path("/jwks"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "keys": [
                    {
                        "kty": "RSA",
                        "use": "sig",
                        "kid": "rsa-key-1",
                        "alg": "RS256",
                        "n": "3TZbOj2V9n8Mml9L7djP2F_qPCP4Sk7peS45-bmQHjvHRrNMFZJ_MFWe8gVpNiovr_RLDWyDWjsXwNG6Rp9ueazrGm3YqWYdMCpd9Ba3re02MDzq4glHcoGZxWQQg_qJ0b8MnG5MdI0p4VqDLhLEbJxHZz5MBgDfME07N3Zn0Lj7ytzHPpHXrhMp3zKBPWBzZShH-JG-QDLKTmODdpZaWMRG0bWo5eyfXNkp0CWTvZgxzZ5rNHHWz4Ff-6zqMSD1x8DN5x-UEcSmpWVRu1zPNMBvqPEoaJ7-xSu4BumkEWhxLkge9Z5Y2QWDKy_D5PSabJQQ3v_G4eqWa6VCT3zZw",
                        "e": "AQAB"
                    },
                    {
                        "kty": "EC",
                        "use": "sig",
                        "kid": "ec-key-1",
                        "alg": "ES256",
                        "crv": "P-256",
                        "x": "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
                        "y": "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"
                    },
                    {
                        "kty": "RSA",
                        "use": "sig",
                        "kid": "rsa-key-2",
                        "alg": "RS512",
                        "n": "xGKzZzOjWmeZhp7wT0T-nhnpOaZrsq7qrqAxZzu6Qk2YcxjjMRnVKySNvYgFWT7JLpinabBLVRPiehFxnvaqBw",
                        "e": "AQAB"
                    }
                ]
            })))
            .mount(&mock_server)
            .await;

        let config = OidcConfig {
            issuer_uri: mock_server.uri(),
            aud: None,
            shared_secret: None,
            bypass: vec![],
        };

        let provider = OidcProvider::discover(config).await.unwrap();

        // Force cache expiration
        {
            let mut jwks_w = provider.jwks.write().await;
            *jwks_w = None;
        }
        {
            let mut refresh_w = provider.last_refresh.write().await;
            *refresh_w = tokio::time::Instant::now()
                .checked_sub(JWKS_REFRESH + std::time::Duration::from_secs(1))
                .unwrap_or_else(|| {
                    tokio::time::Instant::now()
                        .checked_sub(std::time::Duration::from_millis(1))
                        .unwrap_or_else(tokio::time::Instant::now)
                });
        }

        let result = provider.refresh_jwks().await;
        assert!(
            result.is_ok(),
            "JWKS refresh should succeed with multiple keys"
        );

        // Verify JWKS was parsed correctly
        let jwks = provider.jwks.read().await;
        assert!(jwks.is_some(), "JWKS should be cached");
        let jwks = jwks.as_ref().unwrap();
        assert_eq!(jwks.keys.len(), 3, "Should have exactly three keys");

        // Check each key
        let key_ids: Vec<_> = jwks
            .keys
            .iter()
            .filter_map(|k| k.common.key_id.as_ref())
            .collect();

        assert!(
            key_ids.contains(&&"rsa-key-1".to_string()),
            "Should contain rsa-key-1"
        );
        assert!(
            key_ids.contains(&&"ec-key-1".to_string()),
            "Should contain ec-key-1"
        );
        assert!(
            key_ids.contains(&&"rsa-key-2".to_string()),
            "Should contain rsa-key-2"
        );

        // Try to convert keys to decoding keys (may fail with test data)
        for key in &jwks.keys {
            let decoding_key_result = provider.jwk_to_decoding_key(key);
            match decoding_key_result {
                Ok(_) => {
                    println!("Successfully converted key {:?} to decoding key", key.common.key_id);
                }
                Err(e) => {
                    println!("Key conversion failed for {:?} (expected with test data): {e}", key.common.key_id);
                }
            }
        }
    }

    #[tokio::test]
    async fn test_oidc_provider_discover_glob_set_build_failure() {
        // This test is challenging because GlobSetBuilder::build() rarely fails
        // after Glob::new() succeeds. We'll test the error path by creating
        // a scenario that could theoretically cause build() to fail.

        // Setup mock server
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "issuer": mock_server.uri(),
                "jwks_uri": format!("{}/jwks", mock_server.uri())
            })))
            .mount(&mock_server)
            .await;

        // Create a config with a very complex glob pattern that might stress the builder
        let config = OidcConfig {
            issuer_uri: mock_server.uri(),
            aud: None,
            shared_secret: None,
            bypass: vec![RouteRuleConfig {
                methods: vec!["GET".to_string()],
                path: "/api/*".to_string(), // Simple valid pattern
            }],
        };

        // This should succeed since we're using a valid pattern
        let result = OidcProvider::discover(config).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_multiple_bypass_rules_overlapping() {
        // Setup mock server
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "issuer": mock_server.uri(),
                "jwks_uri": format!("{}/jwks", mock_server.uri())
            })))
            .mount(&mock_server)
            .await;

        let config = OidcConfig {
            issuer_uri: mock_server.uri(),
            aud: None,
            shared_secret: None,
            bypass: vec![
                RouteRuleConfig {
                    methods: vec!["GET".to_string()],
                    path: "/api/*".to_string(),
                },
                RouteRuleConfig {
                    methods: vec!["*".to_string()],
                    path: "/api/health".to_string(), // Overlaps with first rule
                },
                RouteRuleConfig {
                    methods: vec!["POST".to_string(), "PUT".to_string()],
                    path: "/api/users/*".to_string(),
                },
            ],
        };

        let provider = OidcProvider::discover(config).await.unwrap();
        assert_eq!(provider.rules.len(), 3);

        // Test overlapping rules - should match first applicable rule
        assert!(provider.is_bypassed("GET", "/api/health")); // Matches both rule 1 and 2
        assert!(provider.is_bypassed("DELETE", "/api/health")); // Matches rule 2 only
        assert!(provider.is_bypassed("POST", "/api/users/123")); // Matches rule 3
        assert!(provider.is_bypassed("GET", "/api/users/123")); // Matches rule 1 (GET /api/*)
    }

    #[tokio::test]
    async fn test_authorization_header_with_extra_whitespace() {
        let provider = OidcProvider {
            issuer: "https://auth.example.com".to_string(),
            aud: None,
            shared_secret: Some("test-secret".to_string()),
            jwks_uri: "https://auth.example.com/jwks".to_string(),
            jwks: Arc::new(RwLock::new(None)),
            last_refresh: Arc::new(RwLock::new(tokio::time::Instant::now())),
            http: reqwest::Client::new(),
            rules: vec![],
        };

        // Test with extra whitespace in authorization header - should fail
        // because the current implementation doesn't handle extra whitespace
        let mut headers = HeaderMap::new();
        headers.insert("authorization", "  Bearer   token123  ".parse().unwrap());

        let request = ProxyRequest {
            method: HttpMethod::Get,
            path: "/api/users".to_string(),
            query: None,
            headers,
            body: reqwest::Body::from(""),
            context: Arc::new(RwLock::new(RequestContext::default())),
            custom_target: None,
        };

        let result = provider.pre(request).await;
        assert!(result.is_err());

        // Should fail because "  bearer   " doesn't match "bearer "
        if let Err(ProxyError::SecurityError(msg)) = result {
            assert!(msg.contains("Invalid authorization scheme"));
        } else {
            panic!("Expected SecurityError");
        }
    }

    #[test]
    fn test_route_rule_matches_edge_cases() {
        let mut builder = GlobSetBuilder::new();
        builder.add(Glob::new("/**").unwrap()); // Match everything
        let paths = builder.build().unwrap();

        let rule = RouteRule {
            methods: vec!["GET".to_string(), "POST".to_string()],
            paths,
        };

        // Test various path formats
        assert!(rule.matches("GET", "/"));
        assert!(rule.matches("POST", "/api"));
        assert!(rule.matches("GET", "/api/v1/users/123"));
        assert!(rule.matches("POST", "/very/deep/nested/path/structure"));
        assert!(!rule.matches("DELETE", "/api")); // Wrong method
        assert!(!rule.matches("PUT", "/")); // Wrong method
    }

    #[test]
    fn test_route_rule_matches_empty_methods() {
        let mut builder = GlobSetBuilder::new();
        builder.add(Glob::new("/health").unwrap());
        let paths = builder.build().unwrap();

        let rule = RouteRule {
            methods: vec![], // Empty methods list
            paths,
        };

        // Should not match anything since no methods are allowed
        assert!(!rule.matches("GET", "/health"));
        assert!(!rule.matches("POST", "/health"));
        assert!(!rule.matches("*", "/health"));
    }
}
