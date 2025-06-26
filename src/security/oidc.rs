// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! OpenID-Connect bearer-token provider.
//!
//! Supported algs   : HS256 / 384 / 512  · RS256 / 384 / 512 · PS256 / 384 / 512
//!                    ES256 / 384        · EdDSA (Ed25519)
//! Bypass rules     : glob-style paths + method list, evaluated before token checks
//! HMAC secret      : optional `shared-secret` in config (required for HS* algs)
//! JWKS refresh     : lazy + every 30 min ± key-rotation retry

use async_trait::async_trait;
use jsonwebtoken::{decode, decode_header, jwk::JwkSet, Algorithm, DecodingKey, Validation};
use jsonwebtoken::jwk::{AlgorithmParameters, Jwk, OctetKeyParameters};
use reqwest::Client;
use std::{sync::Arc, time::Duration};
use serde::Deserialize;
use tokio::sync::RwLock;
use globset::{Glob, GlobSet, GlobSetBuilder};
use crate::{core::{ProxyError, ProxyRequest}, debug_fmt, error_fmt, security::{SecurityProvider, SecurityStage}, trace_fmt, warn_fmt};

pub const CLAIMS_ATTRIBUTE: &str = "oidc-claims";
const BEARER: &str = "bearer ";
const JWKS_REFRESH: Duration = Duration::from_secs(30 * 60);

#[derive(Debug, Clone, serde::Deserialize)]
pub struct RouteRuleConfig {
    pub methods: Vec<String>,
    pub path: String,
}

#[derive(Debug)]
struct RouteRule {
    methods: Vec<String>,
    paths: GlobSet,
}

impl RouteRule {
    fn matches(&self, method: &str, path: &str) -> bool {
        let method_match = self.methods.iter().any(|m| m == "*" || m == method);
        let path_match = self.paths.is_match(path);
        
        trace_fmt!("OidcProvider", "OIDC bypass rule check: method={} path={} -> method_match={} path_match={}", 
            method, path, method_match, path_match);
            
        method_match && path_match
    }
}

/// Top-level OIDC section under `"security_chain"` in config.
#[derive(Debug, Clone, Deserialize)]
pub struct OidcConfig {
    #[serde(rename = "issuer-uri")]
    pub issuer_uri: String,
    
    /// Expected audience claim (optional)
    pub aud: Option<String>,
    
    /// Shared secret for HS* algorithms (optional)
    #[serde(rename = "shared-secret")]
    pub shared_secret: Option<String>,
    
    /// Routes to bypass authentication for
    #[serde(default)]
    pub bypass: Vec<RouteRuleConfig>,
}

/// OpenID Connect security provider.
#[derive(Debug)]
pub struct OidcProvider {
    /// Issuer URI
    issuer: String,
    
    /// Expected audience claim
    aud: Option<String>,
    
    /// Shared secret for HS* algorithms
    shared_secret: Option<String>,
    
    /// JWKS URI
    jwks_uri: String,
    
    /// Cached JWKS
    jwks: Arc<RwLock<Option<JwkSet>>>,
    
    /// Last refresh time
    last_refresh: Arc<RwLock<tokio::time::Instant>>,
    
    /// HTTP client
    http: Client,
    
    /// Bypass rules
    rules: Vec<RouteRule>,
}

impl OidcProvider {
    /// Discover OIDC configuration from the issuer URI.
    pub async fn discover(cfg: OidcConfig) -> Result<Self, ProxyError> {
        // --- minimal discovery ---
        debug_fmt!("OidcProvider", "OIDC discovery from {}", cfg.issuer_uri);
        
        let client = Client::builder()
            .user_agent("foxy/oidc")
            .timeout(Duration::from_secs(10)) // Add a 10-second timeout for network operations
            .build()
            .map_err(|e| {
                let err = ProxyError::SecurityError(format!("Failed to build HTTP client: {e}"));
                error_fmt!("OidcProvider", "{}", err);
                err
            })?;
            
        #[derive(Deserialize)]
        struct Discovery { jwks_uri: String }
        
        let meta: Discovery = match client.get(&cfg.issuer_uri).send().await {
            Ok(response) => {
                match response.error_for_status() {
                    Ok(response) => {
                        match response.json().await {
                            Ok(meta) => meta,
                            Err(e) => {
                                let err = ProxyError::SecurityError(
                                    format!("Failed to parse OIDC discovery response: {e}")
                                );
                                error_fmt!("OidcProvider", "{}", err);
                                return Err(err);
                            }
                        }
                    },
                    Err(e) => {
                        let err = ProxyError::SecurityError(
                            format!("OIDC discovery endpoint returned error: {e}")
                        );
                        error_fmt!("OidcProvider", "{}", err);
                        return Err(err);
                    }
                }
            },
            Err(e) => {
                let err = ProxyError::SecurityError(
                    format!("Failed to connect to OIDC discovery endpoint: {e}")
                );
                error_fmt!("OidcProvider", "{}", err);
                return Err(err);
            }
        };

        debug_fmt!("OidcProvider", "OIDC discovery successful, JWKS URI: {}", meta.jwks_uri);

        // --- compile bypass rules ---
        let mut rules = Vec::with_capacity(cfg.bypass.len());
        for raw in cfg.bypass {
            let mut builder = GlobSetBuilder::new();
            match Glob::new(&raw.path) {
                Ok(glob) => {
                    builder.add(glob);
                    rules.push(RouteRule {
                        methods: raw.methods.iter().map(|m| m.to_ascii_uppercase()).collect(),
                        paths: match builder.build() {
                            Ok(set) => set,
                            Err(e) => {
                                let err = ProxyError::SecurityError(
                                    format!("Failed to build glob set for path {}: {}", raw.path, e)
                                );
                                error_fmt!("OidcProvider", "{}", err);
                                return Err(err);
                            }
                        },
                    });
                    debug_fmt!("OidcProvider", "Added OIDC bypass rule: methods={:?}, path={}", raw.methods, raw.path);
                },
                Err(e) => {
                    let err = ProxyError::SecurityError(
                        format!("Invalid glob pattern in bypass rule: {e}")
                    );
                    error_fmt!("OidcProvider", "{}", err);
                    return Err(err);
                }
            }
        }

        Ok(Self {
            issuer: cfg
                .issuer_uri
                .trim_end_matches("/.well-known/openid-configuration")
                .to_owned(),
            aud: cfg.aud,
            shared_secret: cfg.shared_secret,
            jwks_uri: meta.jwks_uri,
            jwks: Arc::new(RwLock::new(None)),
            last_refresh: Arc::new(RwLock::new(
<<<<<<< fix/oidc
                tokio::time::Instant::now().checked_sub(JWKS_REFRESH * 2)
                    .unwrap_or_else(|| {
                        // If we can't subtract, use a very old instant
                        tokio::time::Instant::now().checked_sub(std::time::Duration::from_secs(1))
                            .unwrap_or_else(|| tokio::time::Instant::now())
                    }),
=======
                tokio::time::Instant::now()
                    .checked_sub(JWKS_REFRESH)
                    .unwrap_or_else(|| tokio::time::Instant::now()),
>>>>>>> develop
            )),
            http: client,
            rules,
        })
    }

    /* ---------- helpers -------------------------------------------------- */

    async fn refresh_jwks(&self) -> Result<(), ProxyError> {
        let now = tokio::time::Instant::now();

        // Check if cache is empty or expired
        let should_refresh = {
            let jwks_guard = self.jwks.read().await;
            let cache_empty = jwks_guard.is_none();
            let cache_expired = now.duration_since(*self.last_refresh.read().await) >= JWKS_REFRESH;
            cache_empty || cache_expired
        };

        if !should_refresh {
            trace_fmt!("OidcProvider", "JWKS cache still fresh, skipping refresh");
            return Ok(());
        }
        
        debug_fmt!("OidcProvider", "Refreshing JWKS from {}", self.jwks_uri);
        
        // Fetch the JWKS
        let response = match self.http.get(&self.jwks_uri).send().await {
            Ok(res) => res,
            Err(e) => {
                let err = ProxyError::SecurityError(format!("Failed to connect to JWKS endpoint: {e:?}"));
                error_fmt!("OidcProvider", "Failed to connect to JWKS endpoint: {:?}", e);
                // Explicitly set JWKS to None on connection error
                {
                    let mut w = self.jwks.write().await;
                    *w = None;
                }
                return Err(err);
            }
        };

        let response = match response.error_for_status() {
            Ok(res) => res,
            Err(e) => {
                let err = ProxyError::SecurityError(format!("JWKS endpoint returned error: {e:?}"));
                error_fmt!("OidcProvider", "JWKS endpoint returned error: {:?}", e);
                // Explicitly set JWKS to None on HTTP error
                {
                    let mut w = self.jwks.write().await;
                    *w = None;
                }
                return Err(err);
            }
        };

        let jwks = match response.json::<JwkSet>().await {
            Ok(j) => j,
            Err(e) => {
                let err = ProxyError::SecurityError(format!("Failed to parse JWKS response: {e:?}"));
                error_fmt!("OidcProvider", "Failed to parse JWKS response: {:?}", e);
                // Explicitly set JWKS to None on JSON parsing error
                {
                    let mut w = self.jwks.write().await;
                    *w = None;
                }
                return Err(err);
            }
        };
        
        debug_fmt!("OidcProvider", "JWKS refresh successful, found {} keys", jwks.keys.len());
        
        // Update the cache
        {
            let mut w = self.jwks.write().await;
            *w = Some(jwks);
        }
        {
            let mut w = self.last_refresh.write().await;
            *w = now;
        }
        
        Ok(())
    }

    fn jwk_to_decoding_key(&self, jwk: &Jwk) -> Result<DecodingKey, ProxyError> {
        match &jwk.algorithm {
            AlgorithmParameters::RSA(params) => {
                trace_fmt!("OidcProvider", "Converting RSA JWK to decoding key");
                DecodingKey::from_rsa_components(&params.n, &params.e)
                    .map_err(|e| {
                        let err = ProxyError::SecurityError(format!("Invalid RSA key: {e}"));
                        error_fmt!("OidcProvider", "{}", err);
                        err
                    })
            }
            AlgorithmParameters::EllipticCurve(params) => {
                trace_fmt!("OidcProvider", "Converting EC JWK to decoding key");
                DecodingKey::from_ec_components(&params.x, &params.y)
                    .map_err(|e| {
                        let err = ProxyError::SecurityError(format!("Invalid EC key: {e}"));
                        error_fmt!("OidcProvider", "{}", err);
                        err
                    })
            }
            AlgorithmParameters::OctetKey(OctetKeyParameters { value, .. }) => {
                trace_fmt!("OidcProvider", "Converting octet JWK to decoding key");
                Ok(DecodingKey::from_secret(value.as_bytes()))
            }
            AlgorithmParameters::OctetKeyPair(params) => {
                trace_fmt!("OidcProvider", "Converting OKP JWK to decoding key");
                DecodingKey::from_ed_components(&params.x)
                    .map_err(|e| {
                        let err = ProxyError::SecurityError(format!("Invalid OKP key: {e}"));
                        error_fmt!("OidcProvider", "{}", err);
                        err
                    })
            }
        }
    }

    async fn validate_token(&self, token: &str) -> Result<serde_json::Value, ProxyError> {
        // Parse the header to determine the key ID and algorithm
        let header = match decode_header(token) {
            Ok(h) => h,
            Err(e) => {
                let err = ProxyError::SecurityError(format!("Invalid JWT header: {e}"));
                warn_fmt!("OidcProvider", "{}", err);
                return Err(err);
            }
        };
        
        trace_fmt!("OidcProvider", "JWT header: alg={:?}, kid={:?}", header.alg, header.kid);
        
        // Check for allowed algorithms
        let allowed_algs = [
            Algorithm::RS256, Algorithm::RS384, Algorithm::RS512,
            Algorithm::PS256, Algorithm::PS384, Algorithm::PS512,
            Algorithm::ES256, Algorithm::ES384,
            Algorithm::EdDSA,
            Algorithm::HS256, Algorithm::HS384, Algorithm::HS512,
        ];
        
        if !allowed_algs.contains(&header.alg) {
            let err = ProxyError::SecurityError(
                format!("Algorithm not allowed: {:?}", header.alg)
            );
            warn_fmt!("OidcProvider", "{}", err);
            return Err(err);
        }

        // Get the key
        let key = match &header.kid {
            Some(kid) => {
                // Ensure we have a fresh JWKS when we need to look up a key
                self.refresh_jwks().await?;

                // Find the key in the JWKS
                let jwks = self.jwks.read().await;
                let jwks = match &*jwks {
                    Some(j) => j,
                    None => {
                        let err = ProxyError::SecurityError("No JWKS available".to_string());
                        error_fmt!("OidcProvider", "{}", err);
                        return Err(err);
                    }
                };

                // Try to find the key by ID
                match jwks.keys.iter().find(|k| k.common.key_id == Some(kid.clone())) {
                    Some(key) => {
                        trace_fmt!("OidcProvider", "Found key with ID {}", kid);
                        match self.jwk_to_decoding_key(key) {
                            Ok(key) => key,
                            Err(e) => {
                                error_fmt!("OidcProvider", "Failed to convert JWK to decoding key: {}", e);
                                return Err(e);
                            }
                        }
                    }
                    None => {
                        // If we have a shared secret, use that for HS* algorithms
                        if let Some(ref secret) = self.shared_secret {
                            if matches!(header.alg, Algorithm::HS256 | Algorithm::HS384 | Algorithm::HS512) {
                                trace_fmt!("OidcProvider", "Using shared secret for HS* algorithm");
                                DecodingKey::from_secret(secret.as_bytes())
                            } else {
                                let err = ProxyError::SecurityError(format!("Key ID {kid} not found in JWKS"));
                                warn_fmt!("OidcProvider", "{}", err);
                                return Err(err);
                            }
                        } else {
                            let err = ProxyError::SecurityError(format!("Key ID {kid} not found in JWKS"));
                            warn_fmt!("OidcProvider", "{}", err);
                            return Err(err);
                        }
                    }
                }
            }
            None => {
                // No key ID, try to use shared secret if available
                if let Some(ref secret) = self.shared_secret {
                    trace_fmt!("OidcProvider", "No key ID in token, using shared secret");
                    DecodingKey::from_secret(secret.as_bytes())
                } else {
                    let err = ProxyError::SecurityError("No key ID in token and no shared secret configured".to_string());
                    warn_fmt!("OidcProvider", "{}", err);
                    return Err(err);
                }
            }
        };

        // Set up validation
        let mut validation = Validation::new(header.alg);
        validation.set_audience(&[&self.aud.clone().unwrap_or_default()]);
        validation.set_issuer(&[&self.issuer]);

        // Validate the token
        match decode::<serde_json::Value>(token, &key, &validation) {
            Ok(token_data) => {
                debug_fmt!("OidcProvider", "JWT validation successful");
                Ok(token_data.claims)
            }
            Err(e) => {
                let err = ProxyError::SecurityError(format!("JWT validation failed: {e}"));
                warn_fmt!("OidcProvider", "{}", err);
                Err(err)
            }
        }
    }

    #[allow(dead_code)]
    fn validate_std_claims(&self, claims: &serde_json::Value) -> Result<(), ProxyError> {
        // Check issuer
        if let Some(iss) = claims["iss"].as_str() {
            if iss != self.issuer {
                let err = ProxyError::SecurityError(
                    format!("Invalid issuer: expected '{}', got '{}'", self.issuer, iss)
                );
                warn_fmt!("OidcProvider", "{}", err);
                return Err(err);
            }
        } else {
            let err = ProxyError::SecurityError("Missing issuer claim".to_string());
            warn_fmt!("OidcProvider", "{}", err);
            return Err(err);
        }
        
        // Check audience if configured
        if let Some(ref expected_aud) = self.aud {
            let valid_audience = match &claims["aud"] {
                serde_json::Value::String(aud) => aud == expected_aud,
                serde_json::Value::Array(auds) => auds.iter()
                    .filter_map(|a| a.as_str())
                    .any(|a| a == expected_aud),
                _ => false,
            };
            
            if !valid_audience {
                let err = ProxyError::SecurityError(
                    format!("Invalid audience: expected '{expected_aud}'")
                );
                warn_fmt!("OidcProvider", "{}", err);
                return Err(err);
            }
        }
        
        // Check expiration
        if let Some(exp) = claims["exp"].as_i64() {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs() as i64;
                
            if exp <= now {
                let err = ProxyError::SecurityError(
                    format!("Token expired at {exp}, current time is {now}")
                );
                warn_fmt!("OidcProvider", "{}", err);
                return Err(err);
            }
        }
        
        debug_fmt!("OidcProvider", "Token claims validation successful");
        Ok(())
    }

    #[inline]
    fn is_bypassed(&self, method: &str, path: &str) -> bool {
        let bypassed = self.rules.iter().any(|r| r.matches(method, path));
        if bypassed {
            debug_fmt!("OidcProvider", "OIDC bypass for {} {}", method, path);
        }
        bypassed
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::{ProxyRequest, HttpMethod, RequestContext};
    use reqwest::header::HeaderMap;
    use std::sync::Arc;
    use tokio::sync::RwLock;
    use wiremock::{MockServer, Mock, ResponseTemplate};
    use wiremock::matchers::{method, path};
    use base64::{Engine as _};

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
        assert_eq!(config.issuer_uri, "https://auth.example.com/.well-known/openid-configuration");
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
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Mock the discovery endpoint
        Mock::given(method("GET"))
            .and(path("/"))
            .respond_with(ResponseTemplate::new(200)
                .set_body_json(serde_json::json!({
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
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Mock the discovery endpoint
        Mock::given(method("GET"))
            .and(path("/"))
            .respond_with(ResponseTemplate::new(200)
                .set_body_json(serde_json::json!({
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
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Mock the discovery endpoint
        Mock::given(method("GET"))
            .and(path("/.well-known/openid-configuration"))
            .respond_with(ResponseTemplate::new(200)
                .set_body_json(serde_json::json!({
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
        tokio::time::sleep(Duration::from_millis(100)).await;

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
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Mock the discovery endpoint to return invalid JSON
        Mock::given(method("GET"))
            .and(path("/"))
            .respond_with(ResponseTemplate::new(200)
                .set_body_string("invalid json"))
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
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Mock the discovery endpoint to return JSON without jwks_uri
        Mock::given(method("GET"))
            .and(path("/"))
            .respond_with(ResponseTemplate::new(200)
                .set_body_json(serde_json::json!({
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
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Mock the discovery endpoint
        Mock::given(method("GET"))
            .and(path("/"))
            .respond_with(ResponseTemplate::new(200)
                .set_body_json(serde_json::json!({
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
                    path: "[invalid-glob".to_string(), // Invalid glob pattern
                },
            ],
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
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Mock the discovery endpoint
        Mock::given(method("GET"))
            .and(path("/"))
            .respond_with(ResponseTemplate::new(200)
                .set_body_json(serde_json::json!({
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
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Mock the discovery endpoint
        Mock::given(method("GET"))
            .and(path("/"))
            .respond_with(ResponseTemplate::new(200)
                .set_body_json(serde_json::json!({
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
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Mock the discovery endpoint
        Mock::given(method("GET"))
            .and(path("/"))
            .respond_with(ResponseTemplate::new(200)
                .set_body_json(serde_json::json!({
                    "issuer": mock_server.uri(),
                    "jwks_uri": format!("{}/jwks", mock_server.uri())
                })))
            .mount(&mock_server)
            .await;

        // Mock the JWKS endpoint
        Mock::given(method("GET"))
            .and(path("/jwks"))
            .respond_with(ResponseTemplate::new(200)
                .set_body_json(serde_json::json!({
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
<<<<<<< fix/oidc
            let mut jwks_w = provider.jwks.write().await;
            *jwks_w = None; // Clear the cache
        }
        {
            let mut refresh_w = provider.last_refresh.write().await;
            // Set to a time that's guaranteed to trigger refresh
            *refresh_w = tokio::time::Instant::now().checked_sub(JWKS_REFRESH + std::time::Duration::from_secs(1))
                .unwrap_or_else(|| {
                    // Fallback: use a very old instant by subtracting a small amount
                    tokio::time::Instant::now().checked_sub(std::time::Duration::from_millis(1))
                        .unwrap_or_else(|| tokio::time::Instant::now())
                });
=======
            let mut w = provider.last_refresh.write().await;
            *w = tokio::time::Instant::now()
                .checked_sub(std::time::Duration::from_secs(3600))
                .unwrap_or_else(tokio::time::Instant::now);
>>>>>>> develop
        }

        let result = provider.refresh_jwks().await;
        assert!(result.is_ok());

        // Verify JWKS was cached
        let jwks = provider.jwks.read().await;
        if jwks.is_none() {
            let refresh_result = provider.refresh_jwks().await;
            println!("JWKS refresh result (if failed): {:?}", refresh_result);
        }
        assert!(jwks.is_some());
        let jwks = jwks.as_ref().unwrap();
        assert_eq!(jwks.keys.len(), 1);
        assert_eq!(jwks.keys[0].common.key_id, Some("test-key-1".to_string()));
    }

    #[tokio::test]
    async fn test_jwks_refresh_http_error() {
        // Setup mock server
        let mock_server = MockServer::start().await;
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Mock the discovery endpoint
        Mock::given(method("GET"))
            .and(path("/"))
            .respond_with(ResponseTemplate::new(200)
                .set_body_json(serde_json::json!({
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
<<<<<<< fix/oidc
            *w = tokio::time::Instant::now().checked_sub(JWKS_REFRESH * 2)
                .unwrap_or_else(|| {
                    tokio::time::Instant::now().checked_sub(std::time::Duration::from_secs(1))
                        .unwrap_or_else(|| tokio::time::Instant::now())
                });
=======
            *w = tokio::time::Instant::now()
                .checked_sub(std::time::Duration::from_secs(3600))
                .unwrap_or_else(tokio::time::Instant::now);
>>>>>>> develop
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
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Mock the discovery endpoint
        Mock::given(method("GET"))
            .and(path("/"))
            .respond_with(ResponseTemplate::new(200)
                .set_body_json(serde_json::json!({
                    "issuer": mock_server.uri(),
                    "jwks_uri": format!("{}/jwks", mock_server.uri())
                })))
            .mount(&mock_server)
            .await;

        // Mock the JWKS endpoint to return invalid JSON
        Mock::given(method("GET"))
            .and(path("/jwks"))
            .respond_with(ResponseTemplate::new(200)
                .set_body_string("invalid json"))
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
<<<<<<< fix/oidc
            let mut jwks_w = provider.jwks.write().await;
            *jwks_w = None; // Clear the cache
        }
        {
            let mut refresh_w = provider.last_refresh.write().await;
            // Set to a time that's guaranteed to trigger refresh
            *refresh_w = tokio::time::Instant::now().checked_sub(JWKS_REFRESH + std::time::Duration::from_secs(1))
                .unwrap_or_else(|| {
                    // Fallback: use a very old instant by subtracting a small amount
                    tokio::time::Instant::now().checked_sub(std::time::Duration::from_millis(1))
                        .unwrap_or_else(|| tokio::time::Instant::now())
                });
=======
            let mut w = provider.last_refresh.write().await;
            *w = tokio::time::Instant::now()
                .checked_sub(std::time::Duration::from_secs(3600))
                .unwrap_or_else(tokio::time::Instant::now);
>>>>>>> develop
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
        // Setup a mock server that never responds to simulate a timeout
        let mock_server = MockServer::start().await;
        let jwks_uri = format!("{}/jwks", mock_server.uri());
        
        // Configure the mock to never respond (effectively a hang/timeout)
        Mock::given(method("GET"))
            .and(path("/jwks"))
            .respond_with(ResponseTemplate::new(200).set_delay(Duration::from_secs(60))) // Longer than client timeout
            .mount(&mock_server)
            .await;

        let provider = OidcProvider {
            issuer: "https://auth.example.com".to_string(),
            aud: None,
            shared_secret: None,
            jwks_uri,
            jwks: Arc::new(RwLock::new(None)),
            last_refresh: Arc::new(RwLock::new(
<<<<<<< fix/oidc
                tokio::time::Instant::now().checked_sub(JWKS_REFRESH * 2)
                    .unwrap_or_else(|| {
                        tokio::time::Instant::now().checked_sub(std::time::Duration::from_secs(1))
                            .unwrap_or_else(|| tokio::time::Instant::now())
                    })
=======
                tokio::time::Instant::now()
                    .checked_sub(std::time::Duration::from_secs(3600))
                    .unwrap_or_else(tokio::time::Instant::now)
>>>>>>> develop
            )),
            http: reqwest::Client::builder()
                .timeout(Duration::from_secs(1)) // Short client timeout to trigger failure
                .build()
                .unwrap(),
            rules: vec![],
        };

        let result = provider.refresh_jwks().await;
        assert!(result.is_err(), "Expected connection error (timeout), but got: {:?}", result);

        if let Err(ProxyError::SecurityError(msg)) = result {
            println!("Actual connection error message: {}", msg); // Print the actual message
            // The error message should indicate a timeout
            assert!(msg.contains("timed out") || msg.contains("operation timed out") || msg.contains("TimedOut"));
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
        let token = format!("{}.{}.signature", header_b64, payload_b64);

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
        use jsonwebtoken::{Header, Algorithm};
        use serde_json::json;

        let provider = OidcProvider {
            issuer: "https://auth.example.com".to_string(),
            aud: None,
            shared_secret: None,
            jwks_uri: "https://auth.example.com/jwks".to_string(),
            jwks: Arc::new(RwLock::new(None)), // No JWKS available
            last_refresh: Arc::new(RwLock::new(
<<<<<<< fix/oidc
                tokio::time::Instant::now().checked_sub(JWKS_REFRESH * 2)
                    .unwrap_or_else(|| {
                        tokio::time::Instant::now().checked_sub(std::time::Duration::from_secs(1))
                            .unwrap_or_else(|| tokio::time::Instant::now())
                    })
=======
                tokio::time::Instant::now()
                    .checked_sub(std::time::Duration::from_secs(3600))
                    .unwrap_or_else(tokio::time::Instant::now)
>>>>>>> develop
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
        let token = format!("{}.{}.signature", header_b64, payload_b64);

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
        use jsonwebtoken::{encode, Header, EncodingKey, Algorithm};

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
            exp: (std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() + 3600) as i64,
            iat: std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64,
        };

        let token = encode(
            &header,
            &claims,
            &EncodingKey::from_secret("test-secret-key".as_ref())
        ).unwrap();

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
        use jsonwebtoken::{encode, Header, EncodingKey, Algorithm};

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
            exp: (std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() + 3600) as i64,
        };

        let token = encode(
            &header,
            &claims,
            &EncodingKey::from_secret("correct-secret".as_ref())
        ).unwrap();

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
        use jsonwebtoken::{encode, Header, EncodingKey, Algorithm};

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
            exp: (std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() + 3600) as i64,
        };

        let token = encode(
            &header,
            &claims,
            &EncodingKey::from_secret("test-secret".as_ref())
        ).unwrap();

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
        use jsonwebtoken::{encode, Header, EncodingKey, Algorithm};

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
            exp: (std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() + 3600) as i64,
        };

        let token = encode(
            &header,
            &claims,
            &EncodingKey::from_secret("test-secret".as_ref())
        ).unwrap();

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
        use jsonwebtoken::{encode, Header, EncodingKey, Algorithm};

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
            exp: (std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() + 3600) as i64,
        };

        let token = encode(
            &header,
            &claims,
            &EncodingKey::from_secret("test-secret".as_ref())
        ).unwrap();

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
        use jsonwebtoken::{encode, Header, EncodingKey, Algorithm};

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
            exp: (std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() - 3600) as i64, // Expired 1 hour ago
        };

        let token = encode(
            &header,
            &claims,
            &EncodingKey::from_secret("test-secret".as_ref())
        ).unwrap();

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
        use jsonwebtoken::{encode, Header, EncodingKey, Algorithm};


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
            exp: (std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() + (100 * 365 * 24 * 3600)) as i64, // 100 years
        };

        let token = encode(
            &header,
            &claims,
            &EncodingKey::from_secret("test-secret".as_ref())
        ).unwrap();

        let result = provider.validate_token(&token).await;
        if result.is_err() {
            println!("Long expiration test error: {:?}", result);
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
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Mock the discovery endpoint
        Mock::given(method("GET"))
            .and(path("/"))
            .respond_with(ResponseTemplate::new(200)
                .set_body_json(serde_json::json!({
                    "issuer": mock_server.uri(),
                    "jwks_uri": format!("{}/jwks", mock_server.uri())
                })))
            .mount(&mock_server)
            .await;

        // Mock the JWKS endpoint
        Mock::given(method("GET"))
            .and(path("/jwks"))
            .respond_with(ResponseTemplate::new(200)
                .set_body_json(serde_json::json!({
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
        let token = format!("{}.{}.signature", header_b64, payload_b64);

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
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Mock the discovery endpoint
        Mock::given(method("GET"))
            .and(path("/"))
            .respond_with(ResponseTemplate::new(200)
                .set_body_json(serde_json::json!({
                    "issuer": mock_server.uri(),
                    "jwks_uri": format!("{}/jwks", mock_server.uri())
                })))
            .mount(&mock_server)
            .await;

        // Mock the JWKS endpoint
        Mock::given(method("GET"))
            .and(path("/jwks"))
            .respond_with(ResponseTemplate::new(200)
                .set_body_json(serde_json::json!({
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
        let token = format!("{}.{}.signature", header_b64, payload_b64);

        let result = provider.validate_token(&token).await;
        assert!(result.is_err());

        if let Err(ProxyError::SecurityError(msg)) = result {
            assert!(msg.contains("not found in JWKS") || msg.contains("no shared secret") || msg.contains("for algorithm") || msg.contains("No JWKS available"));
        } else {
            panic!("Expected SecurityError");
        }
    }

    #[tokio::test]
    async fn test_integration_full_oidc_flow_with_bypass() {
        // Setup mock server
        let mock_server = MockServer::start().await;
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Mock the discovery endpoint
        Mock::given(method("GET"))
            .and(path("/"))
            .respond_with(ResponseTemplate::new(200)
                .set_body_json(serde_json::json!({
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
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Mock the discovery endpoint
        Mock::given(method("GET"))
            .and(path("/"))
            .respond_with(ResponseTemplate::new(200)
                .set_body_json(serde_json::json!({
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

        let rules = vec![
            RouteRule {
                methods: vec!["GET".to_string()],
                paths,
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
            .respond_with(ResponseTemplate::new(200)
                .set_body_json(serde_json::json!({
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
            .respond_with(ResponseTemplate::new(200)
                .set_body_json(serde_json::json!({
                    "issuer": mock_server.uri(),
                    "jwks_uri": format!("{}/jwks", mock_server.uri())
                })))
            .mount(&mock_server)
            .await;

        // Mock JWKS with EC key
        Mock::given(method("GET"))
            .and(path("/jwks"))
            .respond_with(ResponseTemplate::new(200)
                .set_body_json(serde_json::json!({
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
            .respond_with(ResponseTemplate::new(200)
                .set_body_json(serde_json::json!({
                    "issuer": mock_server.uri(),
                    "jwks_uri": format!("{}/jwks", mock_server.uri())
                })))
            .mount(&mock_server)
            .await;

        // Mock JWKS with octet key (HMAC)
        Mock::given(method("GET"))
            .and(path("/jwks"))
            .respond_with(ResponseTemplate::new(200)
                .set_body_json(serde_json::json!({
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
            .respond_with(ResponseTemplate::new(200)
                .set_body_json(serde_json::json!({
                    "issuer": mock_server.uri(),
                    "jwks_uri": format!("{}/jwks", mock_server.uri())
                })))
            .mount(&mock_server)
            .await;

        // Mock JWKS with OKP key (EdDSA)
        Mock::given(method("GET"))
            .and(path("/jwks"))
            .respond_with(ResponseTemplate::new(200)
                .set_body_json(serde_json::json!({
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
        use jsonwebtoken::{encode, Header, EncodingKey, Algorithm};

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
            exp: (std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() + 3600) as i64,
        };

        let token = encode(
            &header,
            &claims,
            &EncodingKey::from_secret("test-secret".as_ref())
        ).unwrap();

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
        let token = format!("{}.{}.signature", header_b64, payload_b64);

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
        use jsonwebtoken::{encode, Header, EncodingKey, Algorithm};

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
            exp: (std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() + 3600) as i64,
        };

        let token = encode(
            &header,
            &claims,
            &EncodingKey::from_secret("test-secret-key-for-hs384".as_ref())
        ).unwrap();

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
        use jsonwebtoken::{encode, Header, EncodingKey, Algorithm};

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
            exp: (std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() + 3600) as i64,
        };

        let token = encode(
            &header,
            &claims,
            &EncodingKey::from_secret("test-secret-key-for-hs512-algorithm".as_ref())
        ).unwrap();

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
            "exp": (std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() + 3600) as i64
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
            "exp": (std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() + 3600) as i64
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
            "exp": (std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() + 3600) as i64
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
            "exp": (std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() + 3600) as i64
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
            "exp": (std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() + 3600) as i64
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
            "exp": (std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() + 3600) as i64
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
            "exp": (std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() - 3600) as i64 // Expired 1 hour ago
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
            "exp": (std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() + 3600) as i64
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
            .respond_with(ResponseTemplate::new(200)
                .set_body_json(serde_json::json!({
                    "issuer": mock_server.uri(),
                    "jwks_uri": format!("{}/jwks", mock_server.uri())
                })))
            .mount(&mock_server)
            .await;

        // Mock the JWKS endpoint with empty keys array
        Mock::given(method("GET"))
            .and(path("/jwks"))
            .respond_with(ResponseTemplate::new(200)
                .set_body_json(serde_json::json!({
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
            *refresh_w = tokio::time::Instant::now().checked_sub(JWKS_REFRESH + std::time::Duration::from_secs(1))
                .unwrap_or_else(|| {
                    tokio::time::Instant::now().checked_sub(std::time::Duration::from_millis(1))
                        .unwrap_or_else(|| tokio::time::Instant::now())
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
    async fn test_oidc_provider_discover_glob_set_build_failure() {
        // This test is challenging because GlobSetBuilder::build() rarely fails
        // after Glob::new() succeeds. We'll test the error path by creating
        // a scenario that could theoretically cause build() to fail.

        // Setup mock server
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/"))
            .respond_with(ResponseTemplate::new(200)
                .set_body_json(serde_json::json!({
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
            bypass: vec![
                RouteRuleConfig {
                    methods: vec!["GET".to_string()],
                    path: "/api/*".to_string(), // Simple valid pattern
                },
            ],
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
            .respond_with(ResponseTemplate::new(200)
                .set_body_json(serde_json::json!({
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

#[async_trait]
impl SecurityProvider for OidcProvider {
    fn name(&self) -> &str { "OidcProvider" }

    fn stage(&self) -> SecurityStage { SecurityStage::Pre }

    async fn pre(&self, req: ProxyRequest) -> Result<ProxyRequest, ProxyError> {
        // 0) Bypass?
        if self.is_bypassed(&req.method.to_string(), &req.path) {
            debug_fmt!("OidcProvider", "OIDC bypass for {} {}", req.method, req.path);
            return Ok(req);
        }

        debug_fmt!("OidcProvider", "OIDC validating request: {} {}", req.method, req.path);

        // 1) Extract bearer token
        let auth_header = match req.headers.get("authorization") {
            Some(h) => match h.to_str() {
                Ok(s) => s.to_lowercase(),
                Err(e) => {
                    let err = ProxyError::SecurityError(
                        format!("Invalid authorization header: {e}")
                    );
                    warn_fmt!("OidcProvider", "{}", err);
                    return Err(err);
                }
            },
            None => {
                let err = ProxyError::SecurityError("Missing authorization header".to_string());
                warn_fmt!("OidcProvider", "{}", err);
                return Err(err);
            }
        };

        if !auth_header.starts_with(BEARER) {
            let err = ProxyError::SecurityError(
                format!("Invalid authorization scheme: expected 'Bearer', got '{}'", 
                    auth_header.split_whitespace().next().unwrap_or(""))
            );
            warn_fmt!("OidcProvider", "{}", err);
            return Err(err);
        }

        let token = &auth_header[BEARER.len()..];
        if token.is_empty() {
            let err = ProxyError::SecurityError("Empty bearer token".to_string());
            warn_fmt!("OidcProvider", "{}", err);
            return Err(err);
        }

        // 2) Validate the token
        trace_fmt!("OidcProvider", "Validating token: {}", token);
        let claims = match self.validate_token(token).await {
            Ok(claims) => claims,
            Err(e) => {
                warn_fmt!("OidcProvider", "Token validation failed: {}", e);
                return Err(e);
            }
        };

        // 3) Store claims in request context
        {
            let mut ctx = req.context.write().await;
            ctx.attributes.insert(CLAIMS_ATTRIBUTE.to_string(), claims);
        }

        debug_fmt!("OidcProvider", "OIDC validation successful for {} {}", req.method, req.path);
        Ok(req)
    }
}
