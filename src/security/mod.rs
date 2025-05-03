// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Security subsystem – runs before/after the main filter pipeline.
//!
//! Initially ships with *zero* providers; downstream crates add their own by
//! implementing [`SecurityProvider`] and registering them on [`ProxyCore`].

pub mod oidc;

use async_trait::async_trait;
use std::{fmt, sync::Arc};
use serde::Deserialize;
use crate::core::{ProxyError, ProxyRequest, ProxyResponse};
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
        Ok(request)
    }

    /// Optionally inspect/validate the response *after* the upstream call.
    async fn post(
        &self,
        _request: ProxyRequest,
        response: ProxyResponse,
    ) -> Result<ProxyResponse, ProxyError> {
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

        for c in cfgs {
            match c {
                ProviderConfig::Oidc { config } => {
                    let p = OidcProvider::discover(config).await?;
                    chain.add(Arc::new(p));
                }
            }
        }

        Ok(chain)
    }

    pub fn add(&mut self, p: Arc<dyn SecurityProvider>) { self.providers.push(p); }

    fn is_bypassed(&self, path: &str) -> bool {
        self.bypass_routes.iter().any(|p| path.starts_with(p))
    }

    pub async fn apply_pre(
        &self,
        mut req: ProxyRequest,
    ) -> Result<ProxyRequest, ProxyError> {
        if self.is_bypassed(&req.path) { return Ok(req); }
        for p in &self.providers {
            if p.stage().is_pre() {
                req = p.pre(req).await
                    .map_err(|e| ProxyError::SecurityError(format!("{}: {e}", p.name())))?;
            }
        }
        Ok(req)
    }

    pub async fn apply_post(
        &self,
        req: ProxyRequest,
        mut resp: ProxyResponse,
    ) -> Result<ProxyResponse, ProxyError> {
        if self.is_bypassed(&req.path) { return Ok(resp); }
        for p in &self.providers {
            if p.stage().is_post() {
                resp = p.post(req.clone(), resp).await
                    .map_err(|e| ProxyError::SecurityError(format!("{}: {e}", p.name())))?;
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
