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

use crate::{
    core::{ProxyError, ProxyRequest},
    debug_fmt, error_fmt,
    security::{SecurityProvider, SecurityStage},
    trace_fmt, warn_fmt,
};
use async_trait::async_trait;
use globset::{Glob, GlobSet, GlobSetBuilder};
use jsonwebtoken::jwk::{AlgorithmParameters, Jwk, OctetKeyParameters};
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header, jwk::JwkSet};
use reqwest::Client;
use serde::Deserialize;
use std::{sync::Arc, time::Duration};
use tokio::sync::RwLock;

pub const CLAIMS_ATTRIBUTE: &str = "oidc-claims";
const BEARER: &str = "bearer ";
pub const JWKS_REFRESH: Duration = Duration::from_secs(30 * 60);

#[derive(Debug, Clone, serde::Deserialize)]
pub struct RouteRuleConfig {
    pub methods: Vec<String>,
    pub path: String,
}

#[derive(Debug)]
pub struct RouteRule {
    pub(crate) methods: Vec<String>,
    pub(crate) paths: GlobSet,
}

impl RouteRule {
    pub(crate) fn matches(&self, method: &str, path: &str) -> bool {
        let method_match = self.methods.iter().any(|m| m == "*" || m == method);
        let path_match = self.paths.is_match(path);

        trace_fmt!(
            "OidcProvider",
            "OIDC bypass rule check: method={} path={} -> method_match={} path_match={}",
            method,
            path,
            method_match,
            path_match
        );

        method_match && path_match
    }
}

/// Top-level OIDC section under `"security_chain"` in config.
#[derive(Debug, Clone, Deserialize)]
pub struct OidcConfig {
    #[serde(rename = "issuer-uri")]
    pub issuer_uri: String,

    /// JWKS URI (required)
    #[serde(rename = "jwks-uri")]
    pub jwks_uri: String,

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
    pub(crate) issuer: String,

    /// Expected audience claim
    pub(crate) aud: Option<String>,

    /// Shared secret for HS* algorithms
    pub(crate) shared_secret: Option<String>,

    /// JWKS URI
    pub(crate) jwks_uri: String,

    /// Cached JWKS
    pub(crate) jwks: Arc<RwLock<Option<JwkSet>>>,

    /// Last refresh time
    pub(crate) last_refresh: Arc<RwLock<tokio::time::Instant>>,

    /// HTTP client
    pub(crate) http: Client,

    /// Bypass rules
    pub(crate) rules: Vec<RouteRule>,
}

impl OidcProvider {
    /// Discover OIDC configuration from the issuer URI.
    pub async fn discover(cfg: OidcConfig) -> Result<Self, ProxyError> {
        let client = Client::builder()
            .user_agent("foxy/oidc")
            .build()
            .map_err(|e| {
                let err = ProxyError::SecurityError(format!("Failed to build HTTP client: {e}"));
                error_fmt!("OidcProvider", "{}", err);
                err
            })?;

        // Use the provided JWKS URI
        let jwks_uri = cfg.jwks_uri.clone();
        debug_fmt!("OidcProvider", "Using JWKS URI: {}", jwks_uri);

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
                                let err = ProxyError::SecurityError(format!(
                                    "Failed to build glob set for path {}: {}",
                                    raw.path, e
                                ));
                                error_fmt!("OidcProvider", "{}", err);
                                return Err(err);
                            }
                        },
                    });
                    debug_fmt!(
                        "OidcProvider",
                        "Added OIDC bypass rule: methods={:?}, path={}",
                        raw.methods,
                        raw.path
                    );
                }
                Err(e) => {
                    let err = ProxyError::SecurityError(format!(
                        "Invalid glob pattern in bypass rule: {e}"
                    ));
                    error_fmt!("OidcProvider", "{}", err);
                    return Err(err);
                }
            }
        }

        Ok(Self {
            issuer: cfg.issuer_uri,
            aud: cfg.aud,
            shared_secret: cfg.shared_secret,
            jwks_uri,
            jwks: Arc::new(RwLock::new(None)),
            last_refresh: Arc::new(RwLock::new(
                tokio::time::Instant::now()
                    .checked_sub(JWKS_REFRESH * 2)
                    .unwrap_or_else(|| {
                        // If we can't subtract, use a very old instant
                        tokio::time::Instant::now()
                            .checked_sub(std::time::Duration::from_secs(1))
                            .unwrap_or_else(tokio::time::Instant::now)
                    }),
            )),
            http: client,
            rules,
        })
    }

    /* ---------- helpers -------------------------------------------------- */

    /// Fallback JWKS parsing for different formats that the standard jsonwebtoken crate might not handle
    fn parse_jwks_fallback(json_value: &serde_json::Value) -> Result<JwkSet, String> {
        // For now, let's implement a simpler fallback that just tries to clean up the JSON
        // and retry with the standard parser

        // Extract the keys array
        let keys_array = json_value
            .get("keys")
            .and_then(|v| v.as_array())
            .ok_or("Missing or invalid 'keys' field")?;

        let mut cleaned_keys = Vec::new();

        for key_value in keys_array {
            if let Some(cleaned_key) = Self::clean_jwk_for_parsing(key_value) {
                cleaned_keys.push(cleaned_key);
            }
        }

        if cleaned_keys.is_empty() {
            return Err("No valid keys found in JWKS after cleaning".to_string());
        }

        let cleaned_jwks = serde_json::json!({
            "keys": cleaned_keys
        });

        // Try to parse the cleaned JWKS
        serde_json::from_value::<JwkSet>(cleaned_jwks)
            .map_err(|e| format!("Failed to parse cleaned JWKS: {e}"))
    }

    /// Clean a single JWK by removing unknown fields and ensuring required fields are present
    fn clean_jwk_for_parsing(key_value: &serde_json::Value) -> Option<serde_json::Value> {
        let obj = key_value.as_object()?;

        // Extract the key type
        let kty = obj.get("kty")?.as_str()?;

        let mut cleaned = serde_json::Map::new();

        // Always include these common fields if present
        for field in &["kty", "kid", "use", "alg"] {
            if let Some(value) = obj.get(*field) {
                cleaned.insert(field.to_string(), value.clone());
            }
        }

        // Include algorithm-specific fields based on key type
        match kty {
            "RSA" => {
                for field in &["n", "e"] {
                    if let Some(value) = obj.get(*field) {
                        cleaned.insert(field.to_string(), value.clone());
                    }
                }
            }
            "EC" => {
                for field in &["x", "y", "crv"] {
                    if let Some(value) = obj.get(*field) {
                        cleaned.insert(field.to_string(), value.clone());
                    }
                }
            }
            "oct" => {
                if let Some(value) = obj.get("k") {
                    cleaned.insert("k".to_string(), value.clone());
                }
            }
            "OKP" => {
                for field in &["x", "crv"] {
                    if let Some(value) = obj.get(*field) {
                        cleaned.insert(field.to_string(), value.clone());
                    }
                }
            }
            _ => {
                // Unknown key type, skip this key
                warn_fmt!("OidcProvider", "Unknown key type in JWKS: {}", kty);
                return None;
            }
        }

        Some(serde_json::Value::Object(cleaned))
    }

    pub(crate) async fn refresh_jwks(&self) -> Result<(), ProxyError> {
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
        let jwks = match self.http.get(&self.jwks_uri).send().await {
            Ok(response) => match response.error_for_status() {
                Ok(response) => {
                    // Get the response text first for better error reporting
                    let response_text = match response.text().await {
                        Ok(text) => text,
                        Err(e) => {
                            let err = ProxyError::SecurityError(format!(
                                "Failed to read JWKS response body: {e}"
                            ));
                            error_fmt!("OidcProvider", "{}", err);
                            return Err(err);
                        }
                    };

                    debug_fmt!("OidcProvider", "JWKS response body: {}", response_text);

                    // Try to parse as JSON first to get better error messages
                    let json_value: serde_json::Value = match serde_json::from_str(&response_text) {
                        Ok(value) => value,
                        Err(e) => {
                            let err = ProxyError::SecurityError(format!(
                                "Failed to parse JWKS response as JSON: {e}. Response body: {}",
                                response_text.chars().take(500).collect::<String>()
                            ));
                            error_fmt!("OidcProvider", "{}", err);
                            return Err(err);
                        }
                    };

                    // Now try to deserialize into JwkSet
                    match serde_json::from_value::<JwkSet>(json_value.clone()) {
                        Ok(jwks) => jwks,
                        Err(e) => {
                            debug_fmt!(
                                "OidcProvider",
                                "Standard JwkSet parsing failed: {}, trying fallback",
                                e
                            );

                            // Try fallback parsing for different JWKS formats
                            match Self::parse_jwks_fallback(&json_value) {
                                Ok(jwks) => {
                                    debug_fmt!("OidcProvider", "Fallback JWKS parsing successful");
                                    jwks
                                }
                                Err(fallback_err) => {
                                    let err = ProxyError::SecurityError(format!(
                                        "Failed to parse JWKS response. Standard error: {e}. Fallback error: {fallback_err}. JSON structure: {}",
                                        serde_json::to_string_pretty(&json_value)
                                            .unwrap_or_else(|_| "invalid".to_string())
                                    ));
                                    error_fmt!("OidcProvider", "{}", err);
                                    return Err(err);
                                }
                            }
                        }
                    }
                }
                Err(e) => {
                    let err =
                        ProxyError::SecurityError(format!("JWKS endpoint returned error: {e}"));
                    error_fmt!("OidcProvider", "{}", err);
                    return Err(err);
                }
            },
            Err(e) => {
                let err =
                    ProxyError::SecurityError(format!("Failed to connect to JWKS endpoint: {e}"));
                error_fmt!("OidcProvider", "{}", err);
                return Err(err);
            }
        };

        debug_fmt!(
            "OidcProvider",
            "JWKS refresh successful, found {} keys",
            jwks.keys.len()
        );

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

    pub(crate) fn jwk_to_decoding_key(&self, jwk: &Jwk) -> Result<DecodingKey, ProxyError> {
        match &jwk.algorithm {
            AlgorithmParameters::RSA(params) => {
                trace_fmt!("OidcProvider", "Converting RSA JWK to decoding key");
                DecodingKey::from_rsa_components(&params.n, &params.e).map_err(|e| {
                    let err = ProxyError::SecurityError(format!("Invalid RSA key: {e}"));
                    error_fmt!("OidcProvider", "{}", err);
                    err
                })
            }
            AlgorithmParameters::EllipticCurve(params) => {
                trace_fmt!("OidcProvider", "Converting EC JWK to decoding key");
                DecodingKey::from_ec_components(&params.x, &params.y).map_err(|e| {
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
                DecodingKey::from_ed_components(&params.x).map_err(|e| {
                    let err = ProxyError::SecurityError(format!("Invalid OKP key: {e}"));
                    error_fmt!("OidcProvider", "{}", err);
                    err
                })
            }
        }
    }

    pub(crate) async fn validate_token(
        &self,
        token: &str,
    ) -> Result<serde_json::Value, ProxyError> {
        // Parse the header to determine the key ID and algorithm
        let header = match decode_header(token) {
            Ok(h) => h,
            Err(e) => {
                let err = ProxyError::SecurityError(format!("Invalid JWT header: {e}"));
                warn_fmt!("OidcProvider", "{}", err);
                return Err(err);
            }
        };

        trace_fmt!(
            "OidcProvider",
            "JWT header: alg={:?}, kid={:?}",
            header.alg,
            header.kid
        );

        // Check for allowed algorithms
        let allowed_algs = [
            Algorithm::RS256,
            Algorithm::RS384,
            Algorithm::RS512,
            Algorithm::PS256,
            Algorithm::PS384,
            Algorithm::PS512,
            Algorithm::ES256,
            Algorithm::ES384,
            Algorithm::EdDSA,
            Algorithm::HS256,
            Algorithm::HS384,
            Algorithm::HS512,
        ];

        if !allowed_algs.contains(&header.alg) {
            let err = ProxyError::SecurityError(format!("Algorithm not allowed: {:?}", header.alg));
            warn_fmt!("OidcProvider", "{}", err);
            return Err(err);
        }

        // SECURITY: Validate algorithm consistency to prevent algorithm confusion attacks
        match header.alg {
            Algorithm::HS256 | Algorithm::HS384 | Algorithm::HS512 => {
                // HMAC algorithms require shared secret and should not have kid when using shared secret
                if self.shared_secret.is_none() {
                    let err = ProxyError::SecurityError(
                        "HMAC algorithms require shared secret configuration".to_string(),
                    );
                    warn_fmt!("OidcProvider", "{}", err);
                    return Err(err);
                }
                // SECURITY: For HMAC algorithms, if kid is present, it must exist in JWKS
                // This prevents fallback to shared secret when kid is specified
                if let Some(ref kid) = header.kid {
                    // Ensure we have a fresh JWKS when we need to look up a key
                    self.refresh_jwks().await?;
                    let jwks = self.jwks.read().await;
                    if let Some(jwks) = &*jwks {
                        if !jwks
                            .keys
                            .iter()
                            .any(|k| k.common.key_id == Some(kid.clone()))
                        {
                            let err = ProxyError::SecurityError(format!(
                                "HMAC algorithm with kid '{kid}' not found in JWKS - potential algorithm confusion attack"
                            ));
                            warn_fmt!("OidcProvider", "{}", err);
                            return Err(err);
                        }
                    }
                }
            }
            _ => {
                // Asymmetric algorithms must have kid
                if header.kid.is_none() {
                    let err = ProxyError::SecurityError(
                        "Asymmetric algorithms require 'kid' (key ID) header".to_string(),
                    );
                    warn_fmt!("OidcProvider", "{}", err);
                    return Err(err);
                }
            }
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
                match jwks
                    .keys
                    .iter()
                    .find(|k| k.common.key_id == Some(kid.clone()))
                {
                    Some(key) => {
                        trace_fmt!("OidcProvider", "Found key with ID {}", kid);
                        match self.jwk_to_decoding_key(key) {
                            Ok(key) => key,
                            Err(e) => {
                                error_fmt!(
                                    "OidcProvider",
                                    "Failed to convert JWK to decoding key: {}",
                                    e
                                );
                                return Err(e);
                            }
                        }
                    }
                    None => {
                        // SECURITY: Only allow shared secret fallback for HMAC algorithms
                        // and only when explicitly configured
                        if let Some(ref secret) = self.shared_secret {
                            if matches!(
                                header.alg,
                                Algorithm::HS256 | Algorithm::HS384 | Algorithm::HS512
                            ) {
                                trace_fmt!(
                                    "OidcProvider",
                                    "Using shared secret for HS* algorithm (no kid provided)"
                                );
                                DecodingKey::from_secret(secret.as_bytes())
                            } else {
                                let err = ProxyError::SecurityError(format!(
                                    "Key ID {kid} not found in JWKS and algorithm {:?} requires asymmetric key",
                                    header.alg
                                ));
                                warn_fmt!("OidcProvider", "{}", err);
                                return Err(err);
                            }
                        } else {
                            let err = ProxyError::SecurityError(format!(
                                "Key ID {kid} not found in JWKS"
                            ));
                            warn_fmt!("OidcProvider", "{}", err);
                            return Err(err);
                        }
                    }
                }
            }
            None => {
                // SECURITY: Only allow shared secret for HMAC algorithms without kid
                // This is the only safe fallback scenario
                if let Some(ref secret) = self.shared_secret {
                    if matches!(
                        header.alg,
                        Algorithm::HS256 | Algorithm::HS384 | Algorithm::HS512
                    ) {
                        trace_fmt!(
                            "OidcProvider",
                            "No key ID in token, using shared secret for HMAC algorithm"
                        );
                        DecodingKey::from_secret(secret.as_bytes())
                    } else {
                        let err = ProxyError::SecurityError(format!(
                            "Algorithm {:?} requires 'kid' (key ID) header for security",
                            header.alg
                        ));
                        warn_fmt!("OidcProvider", "{}", err);
                        return Err(err);
                    }
                } else {
                    let err = ProxyError::SecurityError(
                        "No key ID in token and no shared secret configured".to_string(),
                    );
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
    pub(crate) fn validate_std_claims(&self, claims: &serde_json::Value) -> Result<(), ProxyError> {
        // Check issuer
        if let Some(iss) = claims["iss"].as_str() {
            if iss != self.issuer {
                let err = ProxyError::SecurityError(format!(
                    "Invalid issuer: expected '{}', got '{}'",
                    self.issuer, iss
                ));
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
                serde_json::Value::Array(auds) => auds
                    .iter()
                    .filter_map(|a| a.as_str())
                    .any(|a| a == expected_aud),
                _ => false,
            };

            if !valid_audience {
                let err = ProxyError::SecurityError(format!(
                    "Invalid audience: expected '{expected_aud}'"
                ));
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
                let err = ProxyError::SecurityError(format!(
                    "Token expired at {exp}, current time is {now}"
                ));
                warn_fmt!("OidcProvider", "{}", err);
                return Err(err);
            }
        }

        debug_fmt!("OidcProvider", "Token claims validation successful");
        Ok(())
    }

    #[inline]
    pub(crate) fn is_bypassed(&self, method: &str, path: &str) -> bool {
        let bypassed = self.rules.iter().any(|r| r.matches(method, path));
        if bypassed {
            debug_fmt!("OidcProvider", "OIDC bypass for {} {}", method, path);
        }
        bypassed
    }

    pub(crate) fn extract_bearer_token<'a>(
        &self,
        req: &'a ProxyRequest,
    ) -> Result<&'a str, ProxyError> {
        debug_fmt!(
            "OidcProvider",
            "OIDC validating request: {} {}",
            req.method,
            req.path
        );

        let auth_header = if let Some(h) = req.headers.get("authorization") {
            match h.to_str() {
                Ok(s) => s,
                Err(e) => {
                    let err =
                        ProxyError::SecurityError(format!("Invalid authorization header: {e}"));
                    warn_fmt!("OidcProvider", "{}", err);
                    return Err(err);
                }
            }
        } else {
            let err = ProxyError::SecurityError("Missing authorization header".to_string());
            warn_fmt!("OidcProvider", "{}", err);
            return Err(err);
        };

        if !auth_header.to_lowercase().starts_with(BEARER) {
            let err = ProxyError::SecurityError(format!(
                "Invalid authorization scheme: expected 'Bearer', got '{}'",
                auth_header.split_whitespace().next().unwrap_or("")
            ));
            warn_fmt!("OidcProvider", "{}", err);
            return Err(err);
        }

        let token = &auth_header[BEARER.len()..];
        if token.is_empty() {
            let err = ProxyError::SecurityError("Empty bearer token".to_string());
            warn_fmt!("OidcProvider", "{}", err);
            return Err(err);
        }
        Ok(token)
    }
}

#[async_trait]
impl SecurityProvider for OidcProvider {
    fn name(&self) -> &str {
        "OidcProvider"
    }

    fn stage(&self) -> SecurityStage {
        SecurityStage::Pre
    }

    async fn pre(&self, req: ProxyRequest) -> Result<ProxyRequest, ProxyError> {
        // 0) Bypass?
        if self.is_bypassed(&req.method.to_string(), &req.path) {
            debug_fmt!(
                "OidcProvider",
                "OIDC bypass for {} {}",
                req.method,
                req.path
            );
            return Ok(req);
        }

        // 1) Extract bearer token
        let token = match self.extract_bearer_token(&req) {
            Ok(value) => value,
            Err(value) => return Err(value),
        };

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

        debug_fmt!(
            "OidcProvider",
            "OIDC validation successful for {} {}",
            req.method,
            req.path
        );
        Ok(req)
    }
}
