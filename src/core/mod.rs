// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Core primitives – requests, responses, filters & routing.
//!
//! Everything that physically moves through the proxy pipeline is defined
//! in this module.  No protocol-level logic lives here; that sits in
//! `server.rs` (IO) and `filters.rs` (behaviour).

#[cfg(test)]
mod tests;

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use std::{fmt, mem};
use thiserror::Error;
use crate::security::{ProviderConfig, SecurityChain, SecurityProvider, SecurityStage};
use tokio::sync::RwLock;
use tokio::time::timeout;
use serde::{Serialize, Deserialize};

use crate::config::Config;

/// Errors that can occur during proxy operations.
#[derive(Error, Debug)]
pub enum ProxyError {
    /// HTTP client error
    #[error("HTTP client error: {0}")]
    ClientError(#[from] reqwest::Error),

    /// IO error
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),

    /// Timeout error
    #[error("request timed out after {0:?}")]
    Timeout(Duration),

    /// Router error
    #[error("routing error: {0}")]
    RoutingError(String),

    /// Filter error
    #[error("filter error: {0}")]
    FilterError(String),

    /// Configuration error
    #[error("configuration error: {0}")]
    ConfigError(String),

    /// Security provider error
    #[error("security error: {0}")]
    SecurityError(String),

    /// Generic error
    #[error("{0}")]
    Other(String),
}

impl From<crate::config::error::ConfigError> for ProxyError {
    fn from(err: crate::config::error::ConfigError) -> Self {
        ProxyError::ConfigError(err.to_string())
    }
}

impl From<globset::Error> for ProxyError {
    fn from(e: globset::Error) -> Self {
        ProxyError::SecurityError(e.to_string())
    }
}

impl From<jsonwebtoken::errors::Error> for ProxyError {
    fn from(e: jsonwebtoken::errors::Error) -> Self {
        ProxyError::SecurityError(e.to_string())
    }
}

/// HTTP methods supported by the proxy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum HttpMethod {
    Get,
    Post,
    Put,
    Delete,
    Head,
    Options,
    Patch,
    Trace,
    Connect,
}

impl fmt::Display for HttpMethod {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HttpMethod::Get => write!(f, "GET"),
            HttpMethod::Post => write!(f, "POST"),
            HttpMethod::Put => write!(f, "PUT"),
            HttpMethod::Delete => write!(f, "DELETE"),
            HttpMethod::Head => write!(f, "HEAD"),
            HttpMethod::Options => write!(f, "OPTIONS"),
            HttpMethod::Patch => write!(f, "PATCH"),
            HttpMethod::Trace => write!(f, "TRACE"),
            HttpMethod::Connect => write!(f, "CONNECT"),
        }
    }
}

impl From<&reqwest::Method> for HttpMethod {
    fn from(method: &reqwest::Method) -> Self {
        match *method {
            reqwest::Method::GET => HttpMethod::Get,
            reqwest::Method::POST => HttpMethod::Post,
            reqwest::Method::PUT => HttpMethod::Put,
            reqwest::Method::DELETE => HttpMethod::Delete,
            reqwest::Method::HEAD => HttpMethod::Head,
            reqwest::Method::OPTIONS => HttpMethod::Options,
            reqwest::Method::PATCH => HttpMethod::Patch,
            reqwest::Method::TRACE => HttpMethod::Trace,
            reqwest::Method::CONNECT => HttpMethod::Connect,
            _ => HttpMethod::Get, // Default to GET for unsupported methods
        }
    }
}

impl From<HttpMethod> for reqwest::Method {
    fn from(method: HttpMethod) -> Self {
        match method {
            HttpMethod::Get => reqwest::Method::GET,
            HttpMethod::Post => reqwest::Method::POST,
            HttpMethod::Put => reqwest::Method::PUT,
            HttpMethod::Delete => reqwest::Method::DELETE,
            HttpMethod::Head => reqwest::Method::HEAD,
            HttpMethod::Options => reqwest::Method::OPTIONS,
            HttpMethod::Patch => reqwest::Method::PATCH,
            HttpMethod::Trace => reqwest::Method::TRACE,
            HttpMethod::Connect => reqwest::Method::CONNECT,
        }
    }
}

/// Represents an HTTP request that can be processed by the proxy.
#[derive(Debug)]
pub struct ProxyRequest {
    pub method: HttpMethod,
    pub path: String,
    pub query: Option<String>,
    pub headers: reqwest::header::HeaderMap,
    pub body: reqwest::Body,
    pub context: Arc<RwLock<RequestContext>>,
}

impl Clone for ProxyRequest {
    fn clone(&self) -> Self {
        // A streaming body can't be duplicated.  Give filters an empty one.
        Self {
            method:   self.method,
            path:     self.path.clone(),
            query:    self.query.clone(),
            headers:  self.headers.clone(),
            body:     reqwest::Body::from(""),
            context:  self.context.clone(),
        }
    }
}

/// Represents an HTTP response returned by the proxy.
#[derive(Debug)]
pub struct ProxyResponse {
    pub status: u16,
    pub headers: reqwest::header::HeaderMap,
    pub body: reqwest::Body,
    pub context: Arc<RwLock<ResponseContext>>,
}

/// Context data that can be attached to a request and accessed by filters.
#[derive(Debug, Default, Clone)]
pub struct RequestContext {
    /// The original client's IP address
    pub client_ip: Option<String>,
    /// The start time of the request
    pub start_time: Option<std::time::Instant>,
    /// Custom attributes that can be set by filters
    pub attributes: std::collections::HashMap<String, serde_json::Value>,
}

/// Context data that can be attached to a response and accessed by filters.
#[derive(Debug, Default, Clone)]
pub struct ResponseContext {
    /// The time when the response was received from the target
    pub receive_time: Option<std::time::Instant>,
    /// Custom attributes that can be set by filters
    pub attributes: std::collections::HashMap<String, serde_json::Value>,
}

/// Core proxy server implementation.
#[derive(Debug)]
pub struct ProxyCore {
    /// Configuration for the proxy
    pub config: Arc<Config>,
    /// HTTP client for making outbound requests
    pub client: reqwest::Client,
    /// Router for matching requests to routes
    pub router: Arc<dyn Router>,
    /// Global filters that apply to all routes
    pub global_filters: Arc<RwLock<Vec<Arc<dyn Filter>>>>,
    /// Security chain that applies to all routes
    pub security_chain: Arc<RwLock<SecurityChain>>,
}

impl ProxyCore {
    /// Create a new proxy core with the given configuration and router.
    pub async fn new(config: Arc<Config>, router: Arc<dyn Router>) -> Result<Self, ProxyError> {
        // Configure the HTTP client based on the configuration
        let timeout_secs: u64 = config.get_or_default("proxy.timeout", 30)?;

        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(timeout_secs))
            .build()
            .map_err(ProxyError::ClientError)?;

        let security_config = config
            .get::<Vec<ProviderConfig>>("proxy.security_chain")
            .unwrap_or_default();

        let security_chain = SecurityChain::from_configs(
            security_config.unwrap_or_default()
        ).await?;

        Ok(Self {
            config,
            client,
            router,
            global_filters: Arc::new(RwLock::new(Vec::new())),
            security_chain: Arc::new(RwLock::new(security_chain)),
        })
    }

    /// Add a global filter.
    pub async fn add_global_filter(&self, filter: Arc<dyn Filter>) {
        let mut filters = self.global_filters.write().await;
        filters.push(filter);
    }

    /// Add a security filter to the chain.
    pub async fn add_security_provider(&self, p: Arc<dyn SecurityProvider>) {
        self.security_chain.write().await.add(p);
    }

    /// Process a request through the proxy.
    pub async fn process_request(
        &self,
        mut request: ProxyRequest,
    ) -> Result<ProxyResponse, ProxyError> {
        let overall_start = Instant::now();

        /* ---------- Security chain pre auth ---------- */
        let mut request = self.security_chain.read().await.apply_pre(request).await?;

        /* ---------- PRE-filters ---------- */
        for f in self.global_filters.read().await.iter() {
            if f.filter_type().is_pre() || f.filter_type().is_both() {
                request = f.pre_filter(request).await?;
            }
        }
        let route          = self.router.route(&request).await?;
        let route_filters  = route.filters.clone().unwrap_or_default();
        for f in &route_filters {
            if f.filter_type().is_pre() || f.filter_type().is_both() {
                request = f.pre_filter(request).await?;
            }
        }

        /* ---------- build outbound req ---------- */
        let url = format!("{}{}", route.target_base_url, request.path);
        let outbound_body = mem::replace(&mut request.body, reqwest::Body::from(""));

        let mut builder = self
            .client
            .request(request.method.into(), &url)
            .headers(request.headers.clone())
            .body(outbound_body);

        if let Some(q) = &request.query {
            builder = builder.query(&[(q, "")]);
        }

        /* ---------- send with timeout ---------- */
        let timeout_dur =
            Duration::from_secs(self.config.get_or_default("proxy.timeout", 30)?);

        let upstream_start = Instant::now();
        let resp = timeout(timeout_dur, builder.send())
            .await
            .map_err(|_| ProxyError::Timeout(timeout_dur))?
            .map_err(ProxyError::ClientError)?;
        let upstream_elapsed = upstream_start.elapsed();

        /* ---------- wrap streaming response ---------- */
        let status   = resp.status().as_u16();
        let headers  = resp.headers().clone();
        let body     = reqwest::Body::wrap_stream(resp.bytes_stream());

        let mut proxy_resp = ProxyResponse {
            status,
            headers,
            body,
            context: Arc::new(RwLock::new(ResponseContext::default())),
        };
        proxy_resp.context.write().await.receive_time = Some(Instant::now());

        /* ---------- POST-filters ---------- */
        for f in &route_filters {
            if f.filter_type().is_post() || f.filter_type().is_both() {
                proxy_resp = f.post_filter(request.clone(), proxy_resp).await?;
            }
        }
        for f in self.global_filters.read().await.iter() {
            if f.filter_type().is_post() || f.filter_type().is_both() {
                proxy_resp = f.post_filter(request.clone(), proxy_resp).await?;
            }
        }

        /* ---------- Security chain post auth ---------- */
        proxy_resp = self.security_chain.read().await.apply_post(request.clone(), proxy_resp).await?;
        
        /* ---------- timing log ---------- */
        let overall_elapsed = overall_start.elapsed();
        let internal_elapsed = overall_elapsed.saturating_sub(upstream_elapsed);

        log::debug!(
            "[timing] {} {} -> {} | total={:?} upstream={:?} internal={:?}",
            request.method,
            request.path,
            proxy_resp.status,
            overall_elapsed,
            upstream_elapsed,
            internal_elapsed
        );

        Ok(proxy_resp)
    }
}

/// Describes when a filter should be applied.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FilterType {
    /// Filter applied before the request is sent to the target
    Pre,
    /// Filter applied after the response is received from the target
    Post,
    /// Filter applied both before and after
    Both,
}

impl FilterType {
    /// Returns true if this is a pre-filter or both.
    pub fn is_pre(&self) -> bool {
        matches!(self, FilterType::Pre | FilterType::Both)
    }

    /// Returns true if this is a post-filter or both.
    pub fn is_post(&self) -> bool {
        matches!(self, FilterType::Post | FilterType::Both)
    }

    /// Returns true if this is both a pre and post filter.
    pub fn is_both(&self) -> bool {
        matches!(self, FilterType::Both)
    }
}

/// A filter that processes requests and responses.
#[async_trait::async_trait]
pub trait Filter: fmt::Debug + Send + Sync {
    /// Get the filter type.
    fn filter_type(&self) -> FilterType;

    /// Get the filter name.
    fn name(&self) -> &str;

    /// Process a request before it is sent to the target.
    async fn pre_filter(&self, request: ProxyRequest) -> Result<ProxyRequest, ProxyError> {
        // Default implementation: pass through the request unchanged
        Ok(request)
    }

    /// Process a response after it is received from the target.
    async fn post_filter(&self, _request: ProxyRequest, response: ProxyResponse) -> Result<ProxyResponse, ProxyError> {
        // Default implementation: pass through the response unchanged
        Ok(response)
    }
}

/// A route that the proxy can forward requests to.
#[derive(Debug, Clone)]
pub struct Route {
    /// The ID of the route (for logging and reference)
    pub id: String,
    /// The base URL of the target
    pub target_base_url: String,
    /// The path pattern that this route matches
    pub path_pattern: String,
    /// The filters that should be applied to this route
    pub filters: Option<Vec<Arc<dyn Filter>>>,
}

/// A router that matches requests to routes.
#[async_trait::async_trait]
pub trait Router: fmt::Debug + Send + Sync {
    /// Find a route for the given request.
    async fn route(&self, request: &ProxyRequest) -> Result<Route, ProxyError>;

    /// Get all routes managed by this router.
    async fn get_routes(&self) -> Vec<Route>;

    /// Add a new route to the router.
    async fn add_route(&self, route: Route) -> Result<(), ProxyError>;

    /// Remove a route from the router.
    async fn remove_route(&self, route_id: &str) -> Result<(), ProxyError>;
}
