// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

#[cfg(test)]
mod tests {
    use crate::{
        HttpMethod, ProxyRequest, ProxyResponse, ProxyError,
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
        use crate::security::basic::{BasicAuthConfig, BasicAuthProvider};

        let config = BasicAuthConfig {
            credentials: vec!["user1:pass1".to_string(), "user2:pass2".to_string()],
            bypass: vec![],
        };
        let _provider = BasicAuthProvider::new(config).unwrap();
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
        use crate::security::basic::{BasicAuthConfig, BasicAuthProvider};

        let config = BasicAuthConfig {
            credentials: vec!["user1:pass1".to_string()],
            bypass: vec![],
        };
        let _provider = BasicAuthProvider::new(config).unwrap();
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
        let _provider = BasicAuthProvider::new(config).unwrap();
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

            fn name(&self) -> &str {
                "mock-post-provider"
            }

            async fn post(&self, _request: ProxyRequest, response: ProxyResponse) -> Result<ProxyResponse, ProxyError> {
                if self.should_fail {
                    Err(ProxyError::SecurityError("Mock post-auth failure".to_string()))
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

            fn name(&self) -> &str {
                "mock-post-provider"
            }

            async fn post(&self, _request: ProxyRequest, response: ProxyResponse) -> Result<ProxyResponse, ProxyError> {
                if self.should_fail {
                    Err(ProxyError::SecurityError("Mock post-auth failure".to_string()))
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

            fn name(&self) -> &str {
                "mock-both-provider"
            }

            async fn pre(&self, request: ProxyRequest) -> Result<ProxyRequest, ProxyError> {
                Ok(request)
            }

            async fn post(&self, _request: ProxyRequest, response: ProxyResponse) -> Result<ProxyResponse, ProxyError> {
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
    fn create_test_response(status: u16, headers: Vec<(&'static str, &'static str)>) -> ProxyResponse {
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

        let configs = vec![
            ProviderConfig {
                type_: "unknown_provider".to_string(),
                config: serde_json::json!({}),
            }
        ];

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
        use crate::security::{register_security_provider, SecurityChain, ProviderConfig};


        // Define a custom security provider
        #[derive(Debug)]
        struct CustomSecurityProvider;

        #[async_trait]
        impl SecurityProvider for CustomSecurityProvider {
            fn stage(&self) -> SecurityStage {
                SecurityStage::Pre
            }

            fn name(&self) -> &str {
                "custom"
            }

            async fn pre(&self, request: ProxyRequest) -> Result<ProxyRequest, ProxyError> {
                Ok(request)
            }
        }

        // Register the custom provider
        register_security_provider("custom_test", |_config| {
            Box::pin(async move {
                Ok(Arc::new(CustomSecurityProvider) as Arc<dyn SecurityProvider>)
            })
        });

        // Create a chain using the registered provider
        let configs = vec![
            ProviderConfig {
                type_: "custom_test".to_string(),
                config: serde_json::json!({}),
            }
        ];

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

            fn name(&self) -> &str {
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

            fn name(&self) -> &str {
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
        use crate::security::basic::{BasicAuthConfig, RouteRuleConfig};
        use crate::security::basic::BasicAuthProvider;

        let config = BasicAuthConfig {
            credentials: vec!["user:pass".to_string()],
            bypass: vec![
                RouteRuleConfig {
                    methods: vec!["GET".to_string()],
                    path: "[invalid_glob".to_string(), // Invalid glob pattern
                },
            ],
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
        use crate::security::basic::{RouteRuleConfig, BasicAuthProvider, BasicAuthConfig};

        let config = BasicAuthConfig {
            credentials: vec!["user:pass".to_string()],
            bypass: vec![
                RouteRuleConfig {
                    methods: vec!["*".to_string()], // Wildcard method
                    path: "/public/*".to_string(),
                },
            ],
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
        use crate::security::basic::{RouteRuleConfig, BasicAuthProvider, BasicAuthConfig};

        let config = BasicAuthConfig {
            credentials: vec!["user:pass".to_string()],
            bypass: vec![
                RouteRuleConfig {
                    methods: vec!["GET".to_string(), "POST".to_string()],
                    path: "/api/*".to_string(),
                },
            ],
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
        use crate::security::basic::{RouteRuleConfig, BasicAuthProvider, BasicAuthConfig};

        let config = BasicAuthConfig {
            credentials: vec!["user:pass".to_string()],
            bypass: vec![
                RouteRuleConfig {
                    methods: vec!["GET".to_string()],
                    path: "/api/v*/users/*/profile".to_string(), // Complex glob
                },
            ],
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
        use crate::security::basic::{RouteRuleConfig, BasicAuthProvider, BasicAuthConfig};

        let config = BasicAuthConfig {
            credentials: vec!["user:pass".to_string()],
            bypass: vec![
                RouteRuleConfig {
                    methods: vec!["GET".to_string()],
                    path: "/health".to_string(), // Exact path
                },
            ],
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
        use crate::security::basic::{BasicAuthConfig, RouteRuleConfig, BasicAuthProvider};

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
}
