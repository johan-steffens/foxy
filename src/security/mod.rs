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

use async_trait::async_trait;
use std::{fmt, sync::Arc};
use serde::Deserialize;
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

/// Executes all registered providers, honouring bypass-routes.
#[derive(Debug)]
pub struct SecurityChain {
    providers: Vec<Arc<dyn SecurityProvider>>,
    bypass_routes: Vec<String>,
}

impl SecurityChain {
    pub fn new(bypass_routes: Vec<String>) -> Self {
        Self { providers: Vec::new(), bypass_routes }
    }

    /// Build from raw config list.
    pub async fn from_configs(cfgs: Vec<ProviderConfig>) -> Result<Self, ProxyError> {
        let mut chain = SecurityChain { providers: Vec::new(), bypass_routes: Vec::new() };

        debug_fmt!("SecurityChain", "Building security chain from {} provider configs", cfgs.len());
        
        for c in cfgs {
            match c {
                ProviderConfig::Oidc { config } => {
                    debug_fmt!("SecurityChain", "Initializing OIDC provider with issuer: {}", config.issuer_uri);
                    match OidcProvider::discover(config).await {
                        Ok(p) => {
                            info_fmt!("SecurityChain", "Successfully initialized OIDC provider");
                            chain.add(Arc::new(p));
                        },
                        Err(e) => {
                            error_fmt!("SecurityChain", "Failed to initialize OIDC provider: {}", e);
                            return Err(e);
                        }
                    }
                }
            }
        }

        Ok(chain)
    }

    pub fn add(&mut self, p: Arc<dyn SecurityProvider>) { self.providers.push(p); }

    fn is_bypassed(&self, path: &str) -> bool {
        let bypassed = self.bypass_routes.iter().any(|p| path.starts_with(p));
        if bypassed {
            debug_fmt!("SecurityChain", "Security bypass for path: {}", path);
        }
        bypassed
    }

    pub async fn apply_pre(
        &self,
        mut req: ProxyRequest,
    ) -> Result<ProxyRequest, ProxyError> {
        if self.is_bypassed(&req.path) { 
            return Ok(req); 
        }
        
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
        if self.is_bypassed(&req.path) { 
            return Ok(resp); 
        }
        
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
#[serde(tag = "type", rename_all = "lowercase")]
pub enum ProviderConfig {
    Oidc { config: OidcConfig },
}
