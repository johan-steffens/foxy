// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Built-in filters
//!
//! Filters are **opt-in** – you must reference them in the `filters` array of
//! a `route` for them to execute.  Each filter is documented below together
//! with its configuration schema.

#[cfg(test)]
mod tests;

use std::cmp;
use std::sync::Arc;
use std::time::Instant;
use async_trait::async_trait;
use bytes::Bytes;
use futures_util::{stream, StreamExt, TryStreamExt};
use http_body_util::BodyExt;
use log::{trace, debug, info, warn, error, Level};
use regex::Regex;
use serde::{Serialize, Deserialize};
use once_cell::sync::Lazy;
use std::collections::HashMap;
use std::sync::RwLock;
use futures_util::stream::iter;
use serde_json::Value;

use crate::core::{
    Filter, FilterType, ProxyRequest, ProxyResponse, ProxyError
};
use crate::{HttpMethod, RequestContext};

/// Constructor signature every dynamic filter must implement
pub type FilterConstructor =
fn(serde_json::Value) -> Result<Arc<dyn Filter>, ProxyError>;


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

impl LoggingFilter {
    /// Create a new logging filter with the given configuration.
    pub fn new(config: LoggingFilterConfig) -> Self {
        Self { config }
    }

    /// Create a new logging filter with default configuration.
    pub fn default() -> Self {
        Self::new(LoggingFilterConfig::default())
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
            Level::Error => error!("{}", message),
            Level::Warn => warn!("{}", message),
            Level::Info => info!("{}", message),
            Level::Debug => debug!("{}", message),
            Level::Trace => trace!("{}", message),
        }
    }

    /// Format headers for logging.
    fn format_headers(&self, headers: &reqwest::header::HeaderMap) -> String {
        let mut header_lines = Vec::new();
        for (name, value) in headers.iter() {
            if let Ok(value_str) = value.to_str() {
                header_lines.push(format!("{}: {}", name, value_str));
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
            for (k, v) in request.headers.iter() {
                self.log(&format!(">> {}: {:?}", k, v));
            }
        }
        if self.config.log_request_body {
            let (new_body, snippet) = tee_body(request.body, 1_000).await?;
            let truncated = if snippet.len() == 1000 {"(truncated)"} else {""};
            
            self.log(&format!(">> Request Body:\n{}{}", snippet, truncated));
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
            for (k, v) in response.headers.iter() {
                self.log(&format!("<< {}: {:?}", k, v));
            }
        }
        if self.config.log_response_body {
            let (new_body, snippet) = tee_body(response.body, 1_000).await?;
            let truncated = if snippet.len() == 1000 {"(truncated)"} else {""};

            self.log(&format!(">> Response Body:\n{}{}", snippet, truncated));
            response.body = new_body;
        }
        Ok(response)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouteToServerConfig {
    pub server_list: Vec<String>
}

#[derive(Debug)]
pub struct RouteToServerFilter {
    config:  RouteToServerConfig,
}

impl RouteToServerFilter {
    pub fn new(config: RouteToServerConfig) -> Self {
        Self { config }
    }

    pub fn get_server_list(&self) -> Vec<String> {
        self.config.server_list.clone()
    }

    pub fn get_number_of_servers(&self) -> usize {
        self.config.server_list.len()
    }
}

#[async_trait]
impl Filter for RouteToServerFilter {
    fn filter_type(&self) -> FilterType { FilterType::Pre }

    fn name(&self) -> &str {
        "route_to_server"
    }

    async fn pre_filter(&self, request: ProxyRequest) -> Result<ProxyRequest, ProxyError> {
        let username = get_username(request);
        todo!("determine server")
    }
}

fn get_username(request:ProxyRequest) -> Result<String, ProxyError> {
    let mut username : String = String::from("");

    if let Some(value) = request.clone().headers.get("x-capitec-username"){
        username = String::from(value.to_str().unwrap());
    } else {
        todo!("check body for username")
    }

    Ok((username))
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
    let combined_stream = futures_util::stream::iter(chunks)
        .chain(stream_in.map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e)));
    
    // Wrap the stream back into a reqwest::Body
    let new_body = reqwest::Body::wrap_stream(combined_stream);
    
    // Convert captured bytes to string
    let snippet = String::from_utf8_lossy(&captured).to_string();
    
    Ok((new_body, snippet))
}

/// Configuration for a header modification filter.
#[derive(Debug, Clone, Serialize, Deserialize)]
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

impl Default for HeaderFilterConfig {
    fn default() -> Self {
        Self {
            add_request_headers: std::collections::HashMap::new(),
            remove_request_headers: Vec::new(),
            add_response_headers: std::collections::HashMap::new(),
            remove_response_headers: Vec::new(),
        }
    }
}

/// A filter that modifies HTTP headers.
#[derive(Debug)]
pub struct HeaderFilter {
    config: HeaderFilterConfig,
}

impl HeaderFilter {
    /// Create a new header filter with the given configuration.
    pub fn new(config: HeaderFilterConfig) -> Self {
        Self { config }
    }

    /// Create a new header filter with default configuration.
    pub fn default() -> Self {
        Self::new(HeaderFilterConfig::default())
    }

    /// Apply header modifications to the given header map.
    fn apply_headers(&self, headers: &mut reqwest::header::HeaderMap,
                     add_headers: &std::collections::HashMap<String, String>,
                     remove_headers: &[String]) {
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
                reqwest::header::HeaderValue::from_str(value)
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
            &self.config.remove_request_headers
        );

        Ok(request)
    }

    async fn post_filter(&self, _request: ProxyRequest, mut response: ProxyResponse) -> Result<ProxyResponse, ProxyError> {
        self.apply_headers(
            &mut response.headers,
            &self.config.add_response_headers,
            &self.config.remove_response_headers
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

impl TimeoutFilter {
    /// Create a new timeout filter with the given configuration.
    pub fn new(config: TimeoutFilterConfig) -> Self {
        Self { config }
    }

    /// Create a new timeout filter with default configuration.
    pub fn default() -> Self {
        Self::new(TimeoutFilterConfig::default())
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
        match request.context.write().await {
            mut context => {
                context.attributes.insert(
                    "timeout_ms".to_string(),
                    serde_json::to_value(self.config.timeout_ms).unwrap()
                );
            }
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
        let regex = Regex::new(&config.pattern)
            .map_err(|e| {
                let err = ProxyError::FilterError(format!("Invalid regex pattern '{}': {}", config.pattern, e));
                log::error!("{}", err);
                err
            })?;

        Ok(Self { config, regex })
    }

    /// Create a new path rewrite filter with default configuration.
    pub fn default() -> Result<Self, ProxyError> {
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
            let rewritten_path = self.regex.replace_all(&request.path, &self.config.replacement).to_string();

            if rewritten_path != original_path {
                log::debug!("Rewriting path from {} to {}", original_path, rewritten_path);
                request.path = rewritten_path;
            } else {
                log::trace!("Path rewrite pattern matched but did not change path: {}", original_path);
            }
        }

        Ok(request)
    }

    async fn post_filter(&self, _request: ProxyRequest, response: ProxyResponse) -> Result<ProxyResponse, ProxyError> {
        if self.config.rewrite_response {
            log::debug!("Response path rewriting is configured but not implemented yet");
            // TODO: Implement response path rewriting when needed
            // This would require parsing and modifying the response body
            // which is complex and content-type dependent
        }

        Ok(response)
    }
}

/// Configuration for an alter body filter.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlterBodyFilterConfig {
    pub target_field: String,
    pub target_value: String,
}

impl Default for AlterBodyFilterConfig {
    fn default() -> Self {
        Self {
            target_field: "".to_string(),
            target_value: "".to_string(),
        }
    }
}

/// A filter that allows you to alter a given field in a request body..
#[derive(Debug)]
pub struct AlterBodyFilter {
    config: AlterBodyFilterConfig,
}

impl AlterBodyFilter {
    /// Create a new  alter body filter with the given configuration.
    pub fn new(config: AlterBodyFilterConfig) -> Self {
        Self { config }
    }

    /// Create a new alter body filter with default configuration.
    pub fn default() -> Self {
        Self::new(AlterBodyFilterConfig::default())
    }
}

#[async_trait]
impl Filter for AlterBodyFilter {
    fn filter_type(&self) -> FilterType {
        FilterType::Pre
    }

    fn name(&self) -> &str {
        "alter_body"
    }

    async fn pre_filter(&self, request: ProxyRequest) -> Result<ProxyRequest, ProxyError> {
        let method = request.method;
        let path = request.path;
        let query = request.query;
        let headers = request.headers;
        let context = request.context;

        // Read the stream into a Vec<u8>
        let mut body_stream = request.body.into_data_stream();
        let mut full_body = Vec::new();

        while let Some(chunk_result) = body_stream.next().await {
            match chunk_result {
                Ok(chunk) => full_body.extend_from_slice(&chunk),
                Err(e) => {
                    log::error!("Error reading body chunk: {}", e);
                    break;
                }
            }
        }

        // let mut updated_body = IncommingBody {key1: String::from(""), key2: String::from("")};
        let mut updated_body = "".to_string();

        // Handle the body as a JSON string
        // match String::from_utf8(full_body.clone()) {
        //     Ok(body_str) => {
        //         info!("Request body: {}", body_str);
        //         match serde_json::from_str::<IncommingBody>(&body_str) {
        //             Ok(mut data) => {
        //                 info!("[AFTER PARSE] Request body: {:?}", data);
        //                 data.key1 = self.config.target_value.clone();
        //                 info!("[AFTER ALTER] Request body: {:?}", data);
        //                 updated_body = data;
        //             }
        //             Err(e) => log::error!("Request body is not valid JSON: {}", e),
        //         }
        //     },
        //     Err(e) => log::error!("Request body is not valid UTF-8: {}", e),
        // }

        // Log the body as UTF-8 string
        match String::from_utf8(full_body.clone()) {
            Ok(body_str) => {
                info!("Response body: {}", body_str);
                let mut value: Value = serde_json::from_str(&body_str).unwrap();
                trace!("Response body: {}", value[self.config.target_field.clone()]);
                value[self.config.target_field.clone()] = Value::String(self.config.target_value.clone());
                updated_body = serde_json::to_string(&value).unwrap();
            },
            Err(e) => log::error!("Request body is not valid UTF-8: {}", e),
        }
        
        // let serialized_body =  serde_json::to_string(&updated_body).unwrap();
        // log::info!("[SERIALIZED] Request body: {}", serialized_body);

        // Reconstruct the body so it can still be used
        // let body = reqwest::Body::from(serialized_body);
        let body = reqwest::Body::from(updated_body);

        Ok(ProxyRequest {
            method,
            path,
            query,
            headers,
            body,
            context,
        })
    }
}

/// Configuration for an alter body filter.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InspectBodyFilterConfig {
    pub target_field: String,
}

impl Default for InspectBodyFilterConfig {
    fn default() -> Self {
        Self {
            target_field: "".to_string(),
        }
    }
}

/// A filter that logs out specific values in request bodies.
#[derive(Debug)]
pub struct InspectBodyFilter {
    config: InspectBodyFilterConfig,
}

impl InspectBodyFilter {
    /// Create a new inspect body filter with the given configuration.
    pub fn new(config: InspectBodyFilterConfig) -> Self {
        Self { config }
    }

    /// Create a new inspect body filter with default configuration.
    pub fn default() -> Self {
        Self::new(InspectBodyFilterConfig::default())
    }
}

#[async_trait]
impl Filter for InspectBodyFilter {
    fn filter_type(&self) -> FilterType {
        FilterType::Pre
    }

    fn name(&self) -> &str {
        "inspect_body"
    }

    async fn pre_filter(&self, request: ProxyRequest) -> Result<ProxyRequest, ProxyError> {
        let method = request.method;
        let path = request.path;
        let query = request.query;
        let headers = request.headers;
        let context = request.context;

        // Read the stream into a Vec<u8>
        let mut body_stream = request.body.into_data_stream();
        let mut full_body = Vec::new();

        while let Some(chunk_result) = body_stream.next().await {
            match chunk_result {
                Ok(chunk) => full_body.extend_from_slice(&chunk),
                Err(e) => {
                    log::error!("Error reading body chunk: {}", e);
                    break;
                }
            }
        }

        // Log the body as UTF-8 string
        match String::from_utf8(full_body.clone()) {
            Ok(body_str) => {
                info!("Response body: {}", body_str);
                let value: Value = serde_json::from_str(&body_str).unwrap();
                info!("[Field Inspect] Request body: {:?}", value[self.config.target_field.clone()].as_str().unwrap());

            },
            Err(e) => log::error!("Response body is not valid UTF-8: {}", e),
        }

        // Reconstruct the body so it can still be used
        let body = reqwest::Body::from(full_body);

        Ok(ProxyRequest {
            method,
            path,
            query,
            headers,
            body,
            context,
        })
    }
}

/// Factory for creating filters based on configuration.
#[derive(Debug)]
pub struct FilterFactory;

impl FilterFactory {
    /// Create a filter based on the filter type and configuration.
    pub fn create_filter(filter_type: &str, config: serde_json::Value) -> Result<Arc<dyn Filter>, ProxyError> {
        log::debug!("Creating filter of type '{}' with config: {}", filter_type, config);

        // See if we've got an external filter registered of that name
        if let Some(ctor) = get_registered_filter(filter_type) {
            return ctor(config);
        }
        
        match filter_type {
            "logging" => {
                let config: LoggingFilterConfig = serde_json::from_value(config)
                    .map_err(|e| {
                        let err = ProxyError::FilterError(format!("Invalid logging filter config: {}", e));
                        log::error!("{}", err);
                        err
                    })?;
                Ok(Arc::new(LoggingFilter::new(config)))
            },
            "header" => {
                let config: HeaderFilterConfig = serde_json::from_value(config)
                    .map_err(|e| {
                        let err = ProxyError::FilterError(format!("Invalid header filter config: {}", e));
                        log::error!("{}", err);
                        err
                    })?;
                Ok(Arc::new(HeaderFilter::new(config)))
            },
            "timeout" => {
                let config: TimeoutFilterConfig = serde_json::from_value(config)
                    .map_err(|e| {
                        let err = ProxyError::FilterError(format!("Invalid timeout filter config: {}", e));
                        log::error!("{}", err);
                        err
                    })?;
                Ok(Arc::new(TimeoutFilter::new(config)))
            },
            "path_rewrite" => {
                let config: PathRewriteFilterConfig = serde_json::from_value(config)
                    .map_err(|e| {
                        let err = ProxyError::FilterError(format!("Invalid path rewrite filter config: {}", e));
                        log::error!("{}", err);
                        err
                    })?;
                
                match PathRewriteFilter::new(config) {
                    Ok(filter) => Ok(Arc::new(filter)),
                    Err(e) => {
                        log::error!("Failed to create path rewrite filter: {}", e);
                        Err(e)
                    }
                }
            },
            "alter_body" => {
                let config: AlterBodyFilterConfig = serde_json::from_value(config)
                    .map_err(|e| {
                        let err = ProxyError::FilterError(format!("Invalid alter body filter config: {}", e));
                        log::error!("{}", err);
                        err
                    })?;
                Ok(Arc::new(AlterBodyFilter::new(config)))
            },
            "inspect_body" => {
                let config: InspectBodyFilterConfig = serde_json::from_value(config)
                    .map_err(|e| {
                        let err = ProxyError::FilterError(format!("Invalid inspect body filter config: {}", e));
                        log::error!("{}", err);
                        err
                    })?;
                Ok(Arc::new(InspectBodyFilter::new(config)))
            },
            "route_to_server" => {
                let config: RouteToServerConfig = serde_json::from_value(config)
                    .map_err(|e| {
                        let err = ProxyError::FilterError(format!("Invalid route_to_server filter config: {}", e));
                        log::error!("{}", err);
                        err
                    })?;
                Ok(Arc::new(RouteToServerFilter::new(config)))
            }
            _ => {
                let err = ProxyError::FilterError(format!("Unknown filter type: {}", filter_type));
                log::error!("{}", err);
                Err(err)
            },
        }
    }
}
