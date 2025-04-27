// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Core proxy module for Foxy.
//!
//! This module provides the fundamental HTTP proxy functionality.
//! It handles the routing and forwarding of HTTP requests and responses.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use std::fmt;
use thiserror::Error;
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

    /// Generic error
    #[error("{0}")]
    Other(String),
}

// Implement From<ConfigError> for ProxyError to allow using ? with ConfigError results
impl From<crate::config::error::ConfigError> for ProxyError {
    fn from(err: crate::config::error::ConfigError) -> Self {
        ProxyError::ConfigError(err.to_string())
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
#[derive(Debug, Clone)]
pub struct ProxyRequest {
    /// The HTTP method
    pub method: HttpMethod,
    /// The request path
    pub path: String,
    /// The query string, if any
    pub query: Option<String>,
    /// The request headers
    pub headers: reqwest::header::HeaderMap,
    /// The request body
    pub body: Vec<u8>,
    /// Additional context for the request
    pub context: Arc<RwLock<RequestContext>>,
}

/// Represents an HTTP response returned by the proxy.
#[derive(Debug, Clone)]
pub struct ProxyResponse {
    /// The HTTP status code
    pub status: u16,
    /// The response headers
    pub headers: reqwest::header::HeaderMap,
    /// The response body
    pub body: Vec<u8>,
    /// Additional context for the response
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
    /// Route-specific filters
    pub route_filters: Arc<RwLock<HashMap<String, Vec<Arc<dyn Filter>>>>>,
}

impl ProxyCore {
    /// Create a new proxy core with the given configuration and router.
    pub fn new(config: Arc<Config>, router: Arc<dyn Router>) -> Result<Self, ProxyError> {
        // Configure the HTTP client based on the configuration
        let timeout_secs: u64 = config.get_or_default("proxy.timeout", 30)?;

        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(timeout_secs))
            .build()
            .map_err(ProxyError::ClientError)?;

        Ok(Self {
            config,
            client,
            router,
            global_filters: Arc::new(RwLock::new(Vec::new())),
            route_filters: Arc::new(RwLock::new(HashMap::new())),
        })
    }

    /// Register a filter with the proxy.
    pub async fn add_global_filter(&self, filter: Arc<dyn Filter>) {
        let mut filters = self.global_filters.write().await;
        filters.push(filter);
    }

    pub async fn add_route_filter(&self, route_id: &str, filter: Arc<dyn Filter>) {
        let mut filters = self.route_filters.write().await;
        let route_filters = filters.entry(route_id.to_string()).or_insert_with(Vec::new);
        route_filters.push(filter);
    }

    /// Process a request through the proxy.
    pub async fn process_request(&self, mut request: ProxyRequest) -> Result<ProxyResponse, ProxyError> {
        // 1. Apply global pre-filters
        for filter in self.global_filters.read().await.iter() {
            if filter.filter_type().is_pre() || filter.filter_type().is_both() {
                request = filter.pre_filter(request).await?;
            }
        }

        // 2. Route the request
        let route = self.router.route(&request).await?;

        // 3. Apply route-specific pre-filters
        if let Some(route_filters) = self.route_filters.read().await.get(&route.id) {
            for filter in route_filters.iter() {
                if filter.filter_type().is_pre() || filter.filter_type().is_both() {
                    request = filter.pre_filter(request).await?;
                }
            }
        }

        // 4. Forward the request to the target
        // Use the target_base_url directly without path manipulation
        let target_url = url::Url::parse(&route.target_base_url)
            .map_err(|e| ProxyError::RoutingError(format!("Invalid target URL: {}", e)))?;

        // Determine the path to forward
        let forwarded_path = if target_url.path() == "/" {
            // If the target URL has no path, use the full request path
            request.path.clone()
        } else {
            // For targets with a specific path (like https://httpbin.org/anything),
            // we need to decide what to do with the request path

            // Option 1: Use just the target path (original implementation)
            // target_url.path().to_string()

            // Option 2: Append the request path to the target path
            // However, this might not be what we want if the target path already
            // includes the endpoint (like /anything)

            // Option 3 (recommended): Use path predicate matching to determine which paths to forward
            // If the request path matches a specific pattern, we use the request path directly
            request.path.clone()
        };

        // Construct a new URL with the target scheme+host and the forwarded path
        let mut new_url = target_url.clone();
        new_url.set_path(&forwarded_path);

        // Use the constructed URL for the request
        let mut builder = self.client.request(
            request.method.into(),
            new_url.as_str()
        );

        // Add query parameters if present
        if let Some(query) = &request.query {
            builder = builder.query(&[(query, "")]);
        }

        let request_clone = request.clone();

        // Add headers
        builder = builder.headers(request_clone.headers);

        // Add body if not empty
        if !request.body.is_empty() {
            builder = builder.body(request_clone.body);
        }

        // Get the timeout from configuration or use the default
        let timeout_secs: u64 = self.config.get_or_default("proxy.timeout", 30)?;
        let timeout_duration = Duration::from_secs(timeout_secs);

        // Send the request with a timeout
        let resp = match timeout(timeout_duration, builder.send()).await {
            Ok(Ok(resp)) => resp,
            Ok(Err(e)) => return Err(ProxyError::ClientError(e)),
            Err(_) => return Err(ProxyError::Timeout(timeout_duration)),
        };

        // 5. Convert the response
        let status = resp.status().as_u16();
        let headers = resp.headers().clone();
        let body = resp.bytes().await.map_err(ProxyError::ClientError)?.to_vec();

        let mut response = ProxyResponse {
            status,
            headers,
            body,
            context: Arc::new(RwLock::new(ResponseContext::default())),
        };

        // Set the receive time in the response context
        let mut context = response.context.write().await;
        context.receive_time = Some(std::time::Instant::now());
        drop(context); // Explicitly release the write lock

        // 6. Apply route-specific post-filters
        if let Some(route_filters) = self.route_filters.read().await.get(&route.id) {
            for filter in route_filters.iter() {
                if filter.filter_type().is_post() || filter.filter_type().is_both() {
                    response = filter.post_filter(request.clone(), response).await?;
                }
            }
        }

        // 7. Apply global post-filters
        for filter in self.global_filters.read().await.iter() {
            if filter.filter_type().is_post() || filter.filter_type().is_both() {
                response = filter.post_filter(request.clone(), response).await?;
            }
        }

        Ok(response)
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
    /// The filter IDs that should be applied to this route
    pub filter_ids: Vec<String>,
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