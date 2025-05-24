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
use crate::{core::{ProxyError, ProxyRequest}, security::{SecurityProvider, SecurityStage}};

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
        
        log::trace!("OIDC bypass rule check: method={} path={} -> method_match={} path_match={}", 
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
        log::debug!("OIDC discovery from {}", cfg.issuer_uri);
        
        let client = Client::builder()
            .user_agent("foxy/oidc")
            .build()
            .map_err(|e| {
                let err = ProxyError::SecurityError(format!("Failed to build HTTP client: {}", e));
                log::error!("{}", err);
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
                                    format!("Failed to parse OIDC discovery response: {}", e)
                                );
                                log::error!("{}", err);
                                return Err(err);
                            }
                        }
                    },
                    Err(e) => {
                        let err = ProxyError::SecurityError(
                            format!("OIDC discovery endpoint returned error: {}", e)
                        );
                        log::error!("{}", err);
                        return Err(err);
                    }
                }
            },
            Err(e) => {
                let err = ProxyError::SecurityError(
                    format!("Failed to connect to OIDC discovery endpoint: {}", e)
                );
                log::error!("{}", err);
                return Err(err);
            }
        };

        log::debug!("OIDC discovery successful, JWKS URI: {}", meta.jwks_uri);

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
                                log::error!("{}", err);
                                return Err(err);
                            }
                        },
                    });
                    log::debug!("Added OIDC bypass rule: methods={:?}, path={}", raw.methods, raw.path);
                },
                Err(e) => {
                    let err = ProxyError::SecurityError(
                        format!("Invalid glob pattern in bypass rule: {}", e)
                    );
                    log::error!("{}", err);
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
                tokio::time::Instant::now() - JWKS_REFRESH,
            )),
            http: client,
            rules,
        })
    }

    /* ---------- helpers -------------------------------------------------- */

    async fn refresh_jwks(&self) -> Result<(), ProxyError> {
        let now = tokio::time::Instant::now();
        if now.duration_since(*self.last_refresh.read().await) < JWKS_REFRESH {
            log::trace!("JWKS cache still fresh, skipping refresh");
            return Ok(());
        }
        
        log::debug!("Refreshing JWKS from {}", self.jwks_uri);
        
        // Fetch the JWKS
        let jwks = match self.http.get(&self.jwks_uri).send().await {
            Ok(response) => {
                match response.error_for_status() {
                    Ok(response) => {
                        match response.json::<JwkSet>().await {
                            Ok(jwks) => jwks,
                            Err(e) => {
                                let err = ProxyError::SecurityError(
                                    format!("Failed to parse JWKS response: {}", e)
                                );
                                log::error!("{}", err);
                                return Err(err);
                            }
                        }
                    },
                    Err(e) => {
                        let err = ProxyError::SecurityError(
                            format!("JWKS endpoint returned error: {}", e)
                        );
                        log::error!("{}", err);
                        return Err(err);
                    }
                }
            },
            Err(e) => {
                let err = ProxyError::SecurityError(
                    format!("Failed to connect to JWKS endpoint: {}", e)
                );
                log::error!("{}", err);
                return Err(err);
            }
        };
        
        log::debug!("JWKS refresh successful, found {} keys", jwks.keys.len());
        
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
                log::trace!("Converting RSA JWK to decoding key");
                DecodingKey::from_rsa_components(&params.n, &params.e)
                    .map_err(|e| {
                        let err = ProxyError::SecurityError(format!("Invalid RSA key: {}", e));
                        log::error!("{}", err);
                        err
                    })
            }
            AlgorithmParameters::EllipticCurve(params) => {
                log::trace!("Converting EC JWK to decoding key");
                DecodingKey::from_ec_components(&params.x, &params.y)
                    .map_err(|e| {
                        let err = ProxyError::SecurityError(format!("Invalid EC key: {}", e));
                        log::error!("{}", err);
                        err
                    })
            }
            AlgorithmParameters::OctetKey(OctetKeyParameters { value, .. }) => {
                log::trace!("Converting octet JWK to decoding key");
                Ok(DecodingKey::from_secret(value.as_bytes()))
            }
            AlgorithmParameters::OctetKeyPair(params) => {
                log::trace!("Converting OKP JWK to decoding key");
                DecodingKey::from_ed_components(&params.x)
                    .map_err(|e| {
                        let err = ProxyError::SecurityError(format!("Invalid OKP key: {}", e));
                        log::error!("{}", err);
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
                let err = ProxyError::SecurityError(format!("Invalid JWT header: {}", e));
                log::warn!("{}", err);
                return Err(err);
            }
        };
        
        log::trace!("JWT header: alg={:?}, kid={:?}", header.alg, header.kid);
        
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
            log::warn!("{}", err);
            return Err(err);
        }

        // Ensure we have a fresh JWKS
        self.refresh_jwks().await?;

        // Get the key
        let key = match &header.kid {
            Some(kid) => {
                // Find the key in the JWKS
                let jwks = self.jwks.read().await;
                let jwks = match &*jwks {
                    Some(j) => j,
                    None => {
                        let err = ProxyError::SecurityError("No JWKS available".to_string());
                        log::error!("{}", err);
                        return Err(err);
                    }
                };

                // Try to find the key by ID
                match jwks.keys.iter().find(|k| k.common.key_id == Some(kid.clone())) {
                    Some(key) => {
                        log::trace!("Found key with ID {}", kid);
                        match self.jwk_to_decoding_key(key) {
                            Ok(key) => key,
                            Err(e) => {
                                log::error!("Failed to convert JWK to decoding key: {}", e);
                                return Err(e);
                            }
                        }
                    }
                    None => {
                        // If we have a shared secret, use that for HS* algorithms
                        if let Some(ref secret) = self.shared_secret {
                            if matches!(header.alg, Algorithm::HS256 | Algorithm::HS384 | Algorithm::HS512) {
                                log::trace!("Using shared secret for HS* algorithm");
                                DecodingKey::from_secret(secret.as_bytes())
                            } else {
                                let err = ProxyError::SecurityError(format!("Key ID {} not found in JWKS", kid));
                                log::warn!("{}", err);
                                return Err(err);
                            }
                        } else {
                            let err = ProxyError::SecurityError(format!("Key ID {} not found in JWKS", kid));
                            log::warn!("{}", err);
                            return Err(err);
                        }
                    }
                }
            }
            None => {
                // No key ID, try to use shared secret if available
                if let Some(ref secret) = self.shared_secret {
                    log::trace!("No key ID in token, using shared secret");
                    DecodingKey::from_secret(secret.as_bytes())
                } else {
                    let err = ProxyError::SecurityError("No key ID in token and no shared secret configured".to_string());
                    log::warn!("{}", err);
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
                log::debug!("JWT validation successful");
                Ok(token_data.claims)
            }
            Err(e) => {
                let err = ProxyError::SecurityError(format!("JWT validation failed: {}", e));
                log::warn!("{}", err);
                Err(err)
            }
        }
    }

    fn validate_std_claims(&self, claims: &serde_json::Value) -> Result<(), ProxyError> {
        // Check issuer
        if let Some(iss) = claims["iss"].as_str() {
            if iss != self.issuer {
                let err = ProxyError::SecurityError(
                    format!("Invalid issuer: expected '{}', got '{}'", self.issuer, iss)
                );
                log::warn!("{}", err);
                return Err(err);
            }
        } else {
            let err = ProxyError::SecurityError("Missing issuer claim".to_string());
            log::warn!("{}", err);
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
                    format!("Invalid audience: expected '{}'", expected_aud)
                );
                log::warn!("{}", err);
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
                    format!("Token expired at {}, current time is {}", exp, now)
                );
                log::warn!("{}", err);
                return Err(err);
            }
        }
        
        log::debug!("Token claims validation successful");
        Ok(())
    }

    #[inline]
    fn is_bypassed(&self, method: &str, path: &str) -> bool {
        let bypassed = self.rules.iter().any(|r| r.matches(method, path));
        if bypassed {
            log::debug!("OIDC bypass for {} {}", method, path);
        }
        bypassed
    }
}

#[async_trait]
impl SecurityProvider for OidcProvider {
    fn name(&self) -> &str { "OidcProvider" }

    fn stage(&self) -> SecurityStage { SecurityStage::Pre }

    async fn pre(&self, req: ProxyRequest) -> Result<ProxyRequest, ProxyError> {
        // 0) Bypass?
        if self.is_bypassed(&req.method.to_string(), &req.path) {
            log::debug!("OIDC bypass for {} {}", req.method, req.path);
            return Ok(req);
        }

        log::debug!("OIDC validating request: {} {}", req.method, req.path);

        // 1) Extract bearer token
        let auth_header = match req.headers.get("authorization") {
            Some(h) => match h.to_str() {
                Ok(s) => s.to_lowercase(),
                Err(e) => {
                    let err = ProxyError::SecurityError(
                        format!("Invalid authorization header: {}", e)
                    );
                    log::warn!("{}", err);
                    return Err(err);
                }
            },
            None => {
                let err = ProxyError::SecurityError("Missing authorization header".to_string());
                log::warn!("{}", err);
                return Err(err);
            }
        };

        if !auth_header.starts_with(BEARER) {
            let err = ProxyError::SecurityError(
                format!("Invalid authorization scheme: expected 'Bearer', got '{}'", 
                    auth_header.split_whitespace().next().unwrap_or(""))
            );
            log::warn!("{}", err);
            return Err(err);
        }

        let token = &auth_header[BEARER.len()..];
        if token.is_empty() {
            let err = ProxyError::SecurityError("Empty bearer token".to_string());
            log::warn!("{}", err);
            return Err(err);
        }

        // 2) Validate the token
        log::trace!("Validating token: {}", token);
        let claims = match self.validate_token(token).await {
            Ok(claims) => claims,
            Err(e) => {
                log::warn!("Token validation failed: {}", e);
                return Err(e);
            }
        };

        // 3) Store claims in request context
        {
            let mut ctx = req.context.write().await;
            ctx.attributes.insert(CLAIMS_ATTRIBUTE.to_string(), claims);
        }

        log::debug!("OIDC validation successful for {} {}", req.method, req.path);
        Ok(req)
    }
}
