// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Security subsystem – runs before/after the main filter pipeline.
//!
//! Initially ships with *zero* providers; downstream crates add their own by
//! implementing [`SecurityProvider`] and registering them on [`ProxyCore`].

pub mod oidc;

#[cfg(test)]
mod tests;

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use async_trait::async_trait;
use std::{fmt, sync::Arc};
use once_cell::sync::Lazy;
use serde::Deserialize;
use std::sync::RwLock as StdRwLock;
use crate::core::{ProxyError, ProxyRequest, ProxyResponse};
use crate::{debug_fmt, error_fmt, info_fmt, trace_fmt};
use crate::security::oidc::{OidcConfig, OidcProvider};

/// When in the request/response lifecycle should a provider run?
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecurityStage {
    Pre,
    Post,
    Both,
}

impl SecurityStage {
    pub const fn is_pre(self) -> bool { matches!(self, Self::Pre | Self::Both) }
    pub const fn is_post(self) -> bool { matches!(self, Self::Post | Self::Both) }
}

/// A unit of security logic – e.g. BasicAuth, JWT, OIDC, mTLS …
#[async_trait]
pub trait SecurityProvider: fmt::Debug + Send + Sync {
    /// Which phase(s) does this provider participate in?
    fn stage(&self) -> SecurityStage;
    /// Name shown in logs / error messages.
    fn name(&self) -> &str;

    /// Optionally mutate/validate the inbound request *before* routing.
    async fn pre(
        &self,
        request: ProxyRequest,
    ) -> Result<ProxyRequest, ProxyError> {
        trace_fmt!("SecurityChain", "Security provider '{}' skipping pre-auth (default implementation)", self.name());
        Ok(request)
    }

    /// Optionally inspect/validate the response *after* the upstream call.
    async fn post(
        &self,
        _request: ProxyRequest,
        response: ProxyResponse,
    ) -> Result<ProxyResponse, ProxyError> {
        trace_fmt!("SecurityChain", "Security provider '{}' skipping post-auth (default implementation)", self.name());
        Ok(response)
    }
}

/// Executes all registered providers.
#[derive(Debug)]
pub struct SecurityChain {
    providers: Vec<Arc<dyn SecurityProvider>>,
}

impl SecurityChain {
    pub fn new() -> Self {
        Self { providers: Vec::new() }
    }

    /// Build from raw config list.
    pub async fn from_configs(cfgs: Vec<ProviderConfig>) -> Result<Self, ProxyError> {
        let mut chain = SecurityChain::new();

        debug_fmt!("SecurityChain", "Building security chain from {} provider configs", cfgs.len());

        for c in cfgs {
            let provider = SecurityProviderFactory::create_provider(&c.type_, c.config).await?;
            chain.add(provider);
        }

        Ok(chain)
    }

    pub fn add(&mut self, p: Arc<dyn SecurityProvider>) { self.providers.push(p); }

    pub async fn apply_pre(
        &self,
        mut req: ProxyRequest,
    ) -> Result<ProxyRequest, ProxyError> {
        trace_fmt!("SecurityChain", "Applying security pre-auth chain with {} providers", self.providers.len());

        for p in &self.providers {
            if p.stage().is_pre() {
                trace_fmt!("SecurityChain", "Running pre-auth provider: {}", p.name());
                match p.pre(req).await {
                    Ok(new_req) => {
                        req = new_req;
                    },
                    Err(e) => {
                        let err = ProxyError::SecurityError(format!("{}: {}", p.name(), e));
                        error_fmt!("SecurityChain", "Security pre-auth failed: {}", err);
                        return Err(err);
                    }
                }
            }
        }
        Ok(req)
    }

    pub async fn apply_post(
        &self,
        req: ProxyRequest,
        mut resp: ProxyResponse,
    ) -> Result<ProxyResponse, ProxyError> {
        trace_fmt!("SecurityChain", "Applying security post-auth chain with {} providers", self.providers.len());

        for p in &self.providers {
            if p.stage().is_post() {
                trace_fmt!("SecurityChain", "Running post-auth provider: {}", p.name());
                match p.post(req.clone(), resp).await {
                    Ok(new_resp) => {
                        resp = new_resp;
                    },
                    Err(e) => {
                        let err = ProxyError::SecurityError(format!("{}: {}", p.name(), e));
                        error_fmt!("SecurityChain", "Security post-auth failed: {}", err);
                        return Err(err);
                    }
                }
            }
        }
        Ok(resp)
    }
}

#[derive(Debug, Deserialize)]
pub struct ProviderConfig {
    #[serde(rename = "type")]
    pub type_: String,
    pub config: serde_json::Value,
}


/// Constructor signature every dynamic security provider must implement.
/// Because providers may need to perform async operations (like OIDC discovery),
/// the constructor returns a pinned, boxed future.
pub type SecurityProviderConstructor =
fn(serde_json::Value) -> Pin<Box<dyn Future<Output = Result<Arc<dyn SecurityProvider>, ProxyError>> + Send>>;


/// Global registry for security providers.
static SECURITY_PROVIDER_REGISTRY: Lazy<StdRwLock<HashMap<String, SecurityProviderConstructor>>> =
    Lazy::new(|| StdRwLock::new(HashMap::new()));

/// Register a security provider under a unique name.
pub fn register_security_provider(name: &str, ctor: SecurityProviderConstructor) {
    SECURITY_PROVIDER_REGISTRY
        .write()
        .expect("SECURITY_PROVIDER_REGISTRY poisoned")
        .insert(name.to_string(), ctor);
}

/// Internal helper to get a registered security provider constructor.
fn get_registered_security_provider(name: &str) -> Option<SecurityProviderConstructor> {
    SECURITY_PROVIDER_REGISTRY
        .read()
        .expect("SECURITY_PROVIDER_REGISTRY poisoned")
        .get(name)
        .copied()
}

/// Factory for creating security providers based on configuration.
#[derive(Debug)]
pub struct SecurityProviderFactory;

impl SecurityProviderFactory {
    /// Create a security provider based on its type and configuration.
    pub async fn create_provider(
        provider_type: &str,
        config: serde_json::Value,
    ) -> Result<Arc<dyn SecurityProvider>, ProxyError> {
        debug_fmt!("SecurityProviderFactory", "Creating security provider of type '{}'", provider_type);
        if let Some(ctor) = get_registered_security_provider(provider_type) {
            return ctor(config).await;
        }

        match provider_type {
            "oidc" => {
                let oidc_config: OidcConfig = serde_json::from_value(config)
                    .map_err(|e| ProxyError::SecurityError(format!("Invalid OIDC provider config: {}", e)))?;
                let provider = OidcProvider::discover(oidc_config).await?;
                Ok(Arc::new(provider))
            }
            _ => Err(ProxyError::SecurityError(format!("Unknown security provider type: {}", provider_type))),
        }
    }
}
