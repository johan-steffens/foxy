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
use reqwest::Client;
use std::{sync::Arc, time::Duration};
use serde::Deserialize;
use tokio::sync::RwLock;
use globset::{Glob, GlobSet, GlobSetBuilder};
use jsonwebtoken::jwk::{AlgorithmParameters, Jwk, OctetKeyParameters};
use crate::{core::{ProxyError, ProxyRequest}, security::{SecurityProvider, SecurityStage}, ProxyResponse};

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
        (self.methods.iter().any(|m| m == "*" || m == method))
            && self.paths.is_match(path)
    }
}

/// Top-level OIDC section under `"security_chain"` in config.
#[derive(Debug, Clone, Deserialize)]
pub struct OidcConfig {
    #[serde(rename = "issuer-uri")]
    pub issuer_uri: String,

    #[serde(default)]
    pub aud: Option<String>,

    /// Only required for HS* algorithms.
    #[serde(default, rename = "shared-secret")]
    pub shared_secret: Option<String>,

    #[serde(default, rename = "bypass-routes")]
    pub bypass: Vec<RouteRuleConfig>,
}

/// Convert any supported JWK → DecodingKey.
fn jwk_to_decoding_key(jwk: &Jwk) -> Result<DecodingKey, ProxyError> {
    match &jwk.algorithm {
        AlgorithmParameters::RSA(rsa) => {
            Ok(DecodingKey::from_rsa_components(&rsa.n, &rsa.e)?)
        }
        AlgorithmParameters::EllipticCurve(ec) => {
            Ok(DecodingKey::from_ec_components(&ec.x, &ec.y)?)
        }
        AlgorithmParameters::OctetKey(OctetKeyParameters { value, .. }) => {
            Ok(DecodingKey::from_ed_components(value)?)
        }
        _ => Err(ProxyError::SecurityError("unsupported key type".into())),
    }
}

#[derive(Debug)]
pub struct OidcProvider {
    issuer: String,
    aud: Option<String>,
    shared_secret: Option<String>,

    jwks_uri: String,
    jwks: Arc<RwLock<Option<JwkSet>>>,
    last_refresh: Arc<RwLock<tokio::time::Instant>>,
    http: Client,

    rules: Vec<RouteRule>,
}

impl OidcProvider {
    /* ---------- factory -------------------------------------------------- */

    pub async fn discover(cfg: OidcConfig) -> Result<Self, ProxyError> {
        // --- minimal discovery ---
        let client = Client::builder()
            .user_agent("foxy/oidc")
            .build()?;
        #[derive(Deserialize)]
        struct Discovery { jwks_uri: String }
        let meta: Discovery = client
            .get(&cfg.issuer_uri)
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;

        // --- compile bypass rules ---
        let mut rules = Vec::with_capacity(cfg.bypass.len());
        for raw in cfg.bypass {
            let mut builder = GlobSetBuilder::new();
            builder.add(Glob::new(&raw.path)?);
            rules.push(RouteRule {
                methods: raw.methods.iter().map(|m| m.to_ascii_uppercase()).collect(),
                paths: builder.build()?,
            });
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
            return Ok(());
        }
        let set = self
            .http
            .get(&self.jwks_uri)
            .send()
            .await?
            .error_for_status()?
            .json::<JwkSet>()
            .await?;
        *self.jwks.write().await = Some(set);
        *self.last_refresh.write().await = now;
        Ok(())
    }

    fn validate_std_claims(&self, claims: &serde_json::Value) -> Result<(), ProxyError> {
        if claims["iss"] != self.issuer {
            return Err(ProxyError::SecurityError("bad issuer".into()));
        }
        if let Some(ref aud) = self.aud {
            let ok = claims["aud"]
                .as_str()
                .map(|a| a == aud)
                .unwrap_or(false);
            if !ok {
                return Err(ProxyError::SecurityError("bad audience".into()));
            }
        }
        Ok(())
    }

    #[inline]
    fn is_bypassed(&self, method: &str, path: &str) -> bool {
        self.rules.iter().any(|r| r.matches(method, path))
    }
}

#[async_trait]
impl SecurityProvider for OidcProvider {
    fn name(&self) -> &str { "OidcProvider" }

    fn stage(&self) -> SecurityStage { SecurityStage::Pre }

    async fn pre(&self, mut req: ProxyRequest) -> Result<ProxyRequest, ProxyError> {
        // 0) Bypass?
        if self.is_bypassed(&req.method.to_string(), &req.path) {
            return Ok(req);
        }

        // 1) Extract bearer token
        let auth = req
            .headers
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .ok_or_else(|| ProxyError::SecurityError("missing Authorization".into()))?
            .to_ascii_lowercase();
        if !auth.starts_with(BEARER) {
            return Err(ProxyError::SecurityError("unsupported auth scheme".into()));
        }
        let token = auth.trim_start_matches(BEARER).trim();

        // 2) Decode header / alg / kid
        let header = decode_header(token)?;
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
            return Err(ProxyError::SecurityError("alg not allowed".into()));
        }

        // 3) Build decoding key
        let decoding_key = match header.alg {
            Algorithm::HS256 | Algorithm::HS384 | Algorithm::HS512 => {
                let secret = self.shared_secret.as_deref().ok_or_else(|| {
                    ProxyError::SecurityError("shared-secret not configured".into())
                })?;
                DecodingKey::from_secret(secret.as_bytes())
            }
            _ => {
                self.refresh_jwks().await?;
                let kid = header
                    .kid
                    .ok_or_else(|| ProxyError::SecurityError("missing kid".into()))?;
                
                let jwks_guard = self.jwks.read().await;
                let set = jwks_guard
                    .as_ref()
                    .ok_or_else(|| ProxyError::SecurityError("no JWKS cache".into()))?;

                let jwk = set
                    .find(&kid)
                    .ok_or_else(|| ProxyError::SecurityError("unknown kid".into()))?;
                
                jwk_to_decoding_key(jwk)?
            }
        };

        // 4) Validate signature & std claims
        let mut validation = Validation::new(header.alg);
        validation.set_required_spec_claims(&["exp", "iss"]);

        let data = decode::<serde_json::Value>(token, &decoding_key, &validation)?;
        self.validate_std_claims(&data.claims)?;

        // Expose claims downstream via request.context
        {
            let mut ctx = req.context.write().await;
            ctx.attributes.insert(CLAIMS_ATTRIBUTE.into(), data.claims);
        }

        Ok(req)
    }
}