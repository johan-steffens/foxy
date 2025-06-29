// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Built-in filters
//!
//! Filters are **opt-in** – you must reference them in the `filters` array of
//! a `route` for them to execute.  Each filter is documented below together
//! with its configuration schema.

#[cfg(test)]
#[path = "../../tests/unit/filters/tests.rs"]
mod tests;

use crate::{debug_fmt, error_fmt, info_fmt, trace_fmt, warn_fmt};
use async_trait::async_trait;
use futures_util::{StreamExt, TryStreamExt};
use http_body_util::BodyExt;
use log::Level;
use once_cell::sync::Lazy;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::cmp;
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::RwLock;

use crate::core::{Filter, FilterType, ProxyError, ProxyRequest, ProxyResponse};

/// Constructor signature every dynamic filter must implement
pub type FilterConstructor = fn(serde_json::Value) -> Result<Arc<dyn Filter>, ProxyError>;

/// Global registry – `register_filter()` writes to it,
/// `FilterFactory::create_filter()` reads from it.
static FILTER_REGISTRY: Lazy<RwLock<HashMap<String, FilterConstructor>>> =
    Lazy::new(|| RwLock::new(HashMap::new()));

/// Register a filter under a unique name.
/// Call this **before** you build Foxy:
///
/// ```rust
/// use log::Level::Debug;
/// use foxy::{filters::register_filter, Filter};
///
/// #[derive(Debug)]
/// struct MyFilter;
/// impl MyFilter {
///     fn new(_cfg: serde_json::Value) -> Self { Self }
/// }
///
/// #[async_trait::async_trait]
/// impl foxy::Filter for MyFilter {
///     fn filter_type(&self) -> foxy::FilterType { foxy::FilterType::Pre }
///     fn name(&self) -> &str { "my_filter" }
/// }
///
/// register_filter("my_filter", |cfg| {
///     // turn `cfg` → your filter instance
///     Ok(std::sync::Arc::new(MyFilter::new(cfg)))
/// });
/// ```
pub fn register_filter(name: &str, ctor: FilterConstructor) {
    FILTER_REGISTRY
        .write()
        .expect("FILTER_REGISTRY poisoned")
        .insert(name.to_string(), ctor);
}

/// Internal helper – fetch a constructor if somebody registered one.
fn get_registered_filter(name: &str) -> Option<FilterConstructor> {
    FILTER_REGISTRY
        .read()
        .expect("FILTER_REGISTRY poisoned")
        .get(name)
        .copied()
}

/// Configuration for a logging filter.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggingFilterConfig {
    /// Whether to log request headers
    #[serde(default = "default_true")]
    pub log_request_headers: bool,

    /// Whether to log request body
    #[serde(default = "default_false")]
    pub log_request_body: bool,

    /// Whether to log response headers
    #[serde(default = "default_true")]
    pub log_response_headers: bool,

    /// Whether to log response body
    #[serde(default = "default_false")]
    pub log_response_body: bool,

    /// Log level to use
    #[serde(default = "default_log_level")]
    pub log_level: String,

    /// Maximum body size to log (in bytes)
    #[serde(default = "default_max_body_size")]
    pub max_body_size: usize,
}

fn default_true() -> bool {
    true
}

fn default_false() -> bool {
    false
}

fn default_log_level() -> String {
    "trace".to_string()
}

fn default_max_body_size() -> usize {
    1024 // Default to 1KB
}

impl Default for LoggingFilterConfig {
    fn default() -> Self {
        Self {
            log_request_headers: true,
            log_request_body: false,
            log_response_headers: true,
            log_response_body: false,
            log_level: "trace".to_string(),
            max_body_size: 1024,
        }
    }
}

/// A filter that logs HTTP requests and responses.
#[derive(Debug)]
pub struct LoggingFilter {
    config: LoggingFilterConfig,
}

impl Default for LoggingFilter {
    fn default() -> Self {
        Self::new(LoggingFilterConfig::default())
    }
}

impl LoggingFilter {
    /// Create a new logging filter with the given configuration.
    pub fn new(config: LoggingFilterConfig) -> Self {
        Self { config }
    }

    /// Get the log level from the configuration.
    fn get_log_level(&self) -> Level {
        match self.config.log_level.to_lowercase().as_str() {
            "error" => Level::Error,
            "warn" => Level::Warn,
            "info" => Level::Info,
            "debug" => Level::Debug,
            "trace" => Level::Trace,
            _ => Level::Trace,
        }
    }

    /// Log a message at the configured log level.
    fn log(&self, message: &str) {
        match self.get_log_level() {
            Level::Error => error_fmt!("LoggingFilter", "{}", message),
            Level::Warn => warn_fmt!("LoggingFilter", "{}", message),
            Level::Info => info_fmt!("LoggingFilter", "{}", message),
            Level::Debug => debug_fmt!("LoggingFilter", "{}", message),
            Level::Trace => trace_fmt!("LoggingFilter", "{}", message),
        }
    }

    /// Format headers for logging.
    fn format_headers(&self, headers: &reqwest::header::HeaderMap) -> String {
        let mut header_lines = Vec::new();
        for (name, value) in headers.iter() {
            if let Ok(value_str) = value.to_str() {
                header_lines.push(format!("{name}: {value_str}"));
            }
        }
        header_lines.join("\n")
    }

    /// Format body for logging (with size limits).
    fn format_body(&self, body: &[u8]) -> String {
        if body.is_empty() {
            return "[Empty body]".to_string();
        }

        let body_size = body.len();

        if body_size > self.config.max_body_size {
            return format!(
                "[Body truncated, showing {}/{} bytes]\n{}",
                self.config.max_body_size,
                body_size,
                String::from_utf8_lossy(&body[0..self.config.max_body_size])
            );
        }

        String::from_utf8_lossy(body).to_string()
    }
}

#[async_trait]
impl Filter for LoggingFilter {
    fn filter_type(&self) -> FilterType {
        FilterType::Both
    }

    fn name(&self) -> &str {
        "logging"
    }

    async fn pre_filter(&self, mut request: ProxyRequest) -> Result<ProxyRequest, ProxyError> {
        if self.config.log_request_headers {
            self.log(&format!(">> {} {}", request.method, request.path));
            let formatted_headers = self.format_headers(&request.headers);
            if !formatted_headers.is_empty() {
                for line in formatted_headers.lines() {
                    self.log(&format!(">> {line}"));
                }
            }
        }
        if self.config.log_request_body {
            let (new_body, snippet) = tee_body(request.body, self.config.max_body_size).await?;
            let formatted_body = self.format_body(snippet.as_bytes());
            self.log(&format!(">> Request Body:\n{formatted_body}"));
            request.body = new_body;
        }
        Ok(request)
    }

    async fn post_filter(
        &self,
        _req: ProxyRequest,
        mut response: ProxyResponse,
    ) -> Result<ProxyResponse, ProxyError> {
        if self.config.log_response_headers {
            self.log(&format!("<< {}", response.status));
            let formatted_headers = self.format_headers(&response.headers);
            if !formatted_headers.is_empty() {
                for line in formatted_headers.lines() {
                    self.log(&format!("<< {line}"));
                }
            }
        }
        if self.config.log_response_body {
            let (new_body, snippet) = tee_body(response.body, self.config.max_body_size).await?;
            let formatted_body = self.format_body(snippet.as_bytes());
            self.log(&format!("<< Response Body:\n{formatted_body}"));
            response.body = new_body;
        }
        Ok(response)
    }
}

async fn tee_body(
    body: reqwest::Body,
    limit: usize,
) -> Result<(reqwest::Body, String), ProxyError> {
    // Turn the body into a stream of Bytes
    let mut stream_in = body.into_data_stream();

    // Create a buffer to capture the first `limit` bytes
    let mut captured = Vec::<u8>::with_capacity(limit);

    // Create a vector to collect chunks for replay
    let mut chunks = Vec::new();

    // Read chunks until we have enough bytes or reach EOF
    while captured.len() < limit {
        match stream_in.next().await {
            Some(Ok(chunk)) => {
                // Store the chunk for replay
                let chunk_clone = chunk.clone();
                chunks.push(Ok(chunk));

                // Capture bytes up to the limit
                if captured.len() < limit {
                    let remaining = limit - captured.len();
                    let take = cmp::min(remaining, chunk_clone.len());
                    captured.extend_from_slice(&chunk_clone[..take]);
                }
            }
            Some(Err(e)) => return Err(ProxyError::Other(e.to_string())),
            None => break, // EOF
        }
    }

    // Create a stream that yields our buffered chunks followed by any remaining chunks
    let combined_stream =
        futures_util::stream::iter(chunks).chain(stream_in.map_err(std::io::Error::other));

    // Wrap the stream back into a reqwest::Body
    let new_body = reqwest::Body::wrap_stream(combined_stream);

    // Convert captured bytes to string
    let snippet = String::from_utf8_lossy(&captured).to_string();

    Ok((new_body, snippet))
}

/// Configuration for a header modification filter.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct HeaderFilterConfig {
    /// Headers to add or replace in the request
    #[serde(default)]
    pub add_request_headers: std::collections::HashMap<String, String>,

    /// Headers to remove from the request
    #[serde(default)]
    pub remove_request_headers: Vec<String>,

    /// Headers to add or replace in the response
    #[serde(default)]
    pub add_response_headers: std::collections::HashMap<String, String>,

    /// Headers to remove from the response
    #[serde(default)]
    pub remove_response_headers: Vec<String>,
}

/// A filter that modifies HTTP headers.
#[derive(Debug)]
pub struct HeaderFilter {
    config: HeaderFilterConfig,
}

impl Default for HeaderFilter {
    fn default() -> Self {
        Self::new(HeaderFilterConfig::default())
    }
}

impl HeaderFilter {
    /// Create a new header filter with the given configuration.
    pub fn new(config: HeaderFilterConfig) -> Self {
        Self { config }
    }

    /// Apply header modifications to the given header map.
    fn apply_headers(
        &self,
        headers: &mut reqwest::header::HeaderMap,
        add_headers: &std::collections::HashMap<String, String>,
        remove_headers: &[String],
    ) {
        // Remove headers
        for header_name in remove_headers {
            if let Ok(name) = reqwest::header::HeaderName::from_bytes(header_name.as_bytes()) {
                headers.remove(&name);
            }
        }

        // Add or replace headers
        for (name, value) in add_headers {
            if let (Ok(header_name), Ok(header_value)) = (
                reqwest::header::HeaderName::from_bytes(name.as_bytes()),
                reqwest::header::HeaderValue::from_str(value),
            ) {
                headers.insert(header_name, header_value);
            }
        }
    }
}

#[async_trait]
impl Filter for HeaderFilter {
    fn filter_type(&self) -> FilterType {
        FilterType::Both
    }

    fn name(&self) -> &str {
        "header"
    }

    async fn pre_filter(&self, mut request: ProxyRequest) -> Result<ProxyRequest, ProxyError> {
        self.apply_headers(
            &mut request.headers,
            &self.config.add_request_headers,
            &self.config.remove_request_headers,
        );

        Ok(request)
    }

    async fn post_filter(
        &self,
        _request: ProxyRequest,
        mut response: ProxyResponse,
    ) -> Result<ProxyResponse, ProxyError> {
        self.apply_headers(
            &mut response.headers,
            &self.config.add_response_headers,
            &self.config.remove_response_headers,
        );

        Ok(response)
    }
}

/// Configuration for a timeout filter.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeoutFilterConfig {
    /// Timeout in milliseconds
    pub timeout_ms: u64,
}

impl Default for TimeoutFilterConfig {
    fn default() -> Self {
        Self {
            timeout_ms: 30000, // 30 seconds
        }
    }
}

/// A filter that enforces request timeouts.
#[derive(Debug)]
pub struct TimeoutFilter {
    config: TimeoutFilterConfig,
}

impl Default for TimeoutFilter {
    fn default() -> Self {
        Self::new(TimeoutFilterConfig::default())
    }
}

impl TimeoutFilter {
    /// Create a new timeout filter with the given configuration.
    pub fn new(config: TimeoutFilterConfig) -> Self {
        Self { config }
    }
}

#[async_trait]
impl Filter for TimeoutFilter {
    fn filter_type(&self) -> FilterType {
        FilterType::Pre
    }

    fn name(&self) -> &str {
        "timeout"
    }

    async fn pre_filter(&self, request: ProxyRequest) -> Result<ProxyRequest, ProxyError> {
        // Store the timeout in the request context
        {
            let mut context = request.context.write().await;
            context.attributes.insert(
                "timeout_ms".to_string(),
                serde_json::to_value(self.config.timeout_ms).unwrap(),
            );
        }

        Ok(request)
    }
}

/// Configuration for a path rewrite filter.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PathRewriteFilterConfig {
    /// The pattern to match (regex)
    pub pattern: String,
    /// The replacement pattern
    pub replacement: String,
    /// Whether to apply on the request path
    #[serde(default = "default_true")]
    pub rewrite_request: bool,
    /// Whether to apply on the response path (if found in headers or body)
    #[serde(default = "default_false")]
    pub rewrite_response: bool,
}

/// A filter that rewrites request and response paths based on regex patterns.
#[derive(Debug)]
pub struct PathRewriteFilter {
    /// The configuration for this filter
    config: PathRewriteFilterConfig,
    /// Compiled regex for path matching
    regex: Regex,
}

impl PathRewriteFilter {
    /// Create a new path rewrite filter with the given configuration.
    pub fn new(config: PathRewriteFilterConfig) -> Result<Self, ProxyError> {
        // Compile the regex
        let regex = Regex::new(&config.pattern).map_err(|e| {
            let err = ProxyError::FilterError(format!(
                "Invalid regex pattern '{}': {}",
                config.pattern, e
            ));
            error_fmt!("PathRewriteFilter", "{}", err);
            err
        })?;

        Ok(Self { config, regex })
    }

    /// Create a new path rewrite filter with default configuration.
    pub fn with_defaults() -> Result<Self, ProxyError> {
        Self::new(PathRewriteFilterConfig {
            pattern: "(.*)".to_string(),
            replacement: "$1".to_string(),
            rewrite_request: true,
            rewrite_response: false,
        })
    }
}

#[async_trait]
impl Filter for PathRewriteFilter {
    fn filter_type(&self) -> FilterType {
        FilterType::Both
    }

    fn name(&self) -> &str {
        "path_rewrite"
    }

    async fn pre_filter(&self, mut request: ProxyRequest) -> Result<ProxyRequest, ProxyError> {
        if self.config.rewrite_request {
            // Apply path rewriting on the request path
            let original_path = request.path.clone();
            let rewritten_path = self
                .regex
                .replace_all(&request.path, &self.config.replacement)
                .to_string();

            if rewritten_path != original_path {
                debug_fmt!(
                    "PathRewriteFilter",
                    "Rewriting path from {} to {}",
                    original_path,
                    rewritten_path
                );
                request.path = rewritten_path;
            } else {
                trace_fmt!(
                    "PathRewriteFilter",
                    "Path rewrite pattern matched but did not change path: {}",
                    original_path
                );
            }
        }

        Ok(request)
    }

    async fn post_filter(
        &self,
        _request: ProxyRequest,
        response: ProxyResponse,
    ) -> Result<ProxyResponse, ProxyError> {
        if self.config.rewrite_response {
            debug_fmt!(
                "PathRewriteFilter",
                "Response path rewriting is configured but not implemented yet"
            );
            // TODO: Implement response path rewriting when needed
            // This would require parsing and modifying the response body
            // which is complex and content-type dependent
        }

        Ok(response)
    }
}

/// Factory for creating filters based on configuration.
#[derive(Debug)]
pub struct FilterFactory;

impl FilterFactory {
    /// Create a filter based on the filter type and configuration.
    pub fn create_filter(
        filter_type: &str,
        config: serde_json::Value,
    ) -> Result<Arc<dyn Filter>, ProxyError> {
        debug_fmt!(
            "Filter",
            "Creating filter of type '{}' with config: {}",
            filter_type,
            config
        );

        // See if we've got an external filter registered of that name
        if let Some(ctor) = get_registered_filter(filter_type) {
            return ctor(config);
        }

        match filter_type {
            "logging" => {
                let config: LoggingFilterConfig = serde_json::from_value(config).map_err(|e| {
                    let err =
                        ProxyError::FilterError(format!("Invalid logging filter config: {e}"));
                    error_fmt!("Filter", "{}", err);
                    err
                })?;
                Ok(Arc::new(LoggingFilter::new(config)))
            }
            "header" => {
                let config: HeaderFilterConfig = serde_json::from_value(config).map_err(|e| {
                    let err = ProxyError::FilterError(format!("Invalid header filter config: {e}"));
                    error_fmt!("Filter", "{}", err);
                    err
                })?;
                Ok(Arc::new(HeaderFilter::new(config)))
            }
            "timeout" => {
                let config: TimeoutFilterConfig = serde_json::from_value(config).map_err(|e| {
                    let err =
                        ProxyError::FilterError(format!("Invalid timeout filter config: {e}"));
                    error_fmt!("Filter", "{}", err);
                    err
                })?;
                Ok(Arc::new(TimeoutFilter::new(config)))
            }
            "path_rewrite" => {
                let config: PathRewriteFilterConfig =
                    serde_json::from_value(config).map_err(|e| {
                        let err = ProxyError::FilterError(format!(
                            "Invalid path rewrite filter config: {e}"
                        ));
                        error_fmt!("Filter", "{}", err);
                        err
                    })?;

                match PathRewriteFilter::new(config) {
                    Ok(filter) => Ok(Arc::new(filter)),
                    Err(e) => {
                        error_fmt!("Filter", "Failed to create path rewrite filter: {}", e);
                        Err(e)
                    }
                }
            }
            _ => {
                let err = ProxyError::FilterError(format!("Unknown filter type: {filter_type}"));
                error_fmt!("Filter", "{}", err);
                Err(err)
            }
        }
    }
}
