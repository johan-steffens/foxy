// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Filters for processing HTTP requests and responses.
//!
//! This module provides various filters that can modify or log HTTP requests
//! and responses as they flow through the proxy.

use std::sync::Arc;
use std::time::Instant;
use async_trait::async_trait;
use log::{trace, debug, info, warn, error, Level};
use regex::Regex;
use serde::{Serialize, Deserialize};

use crate::core::{
    Filter, FilterType, ProxyRequest, ProxyResponse, ProxyError
};

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

    async fn pre_filter(&self, request: ProxyRequest) -> Result<ProxyRequest, ProxyError> {
        self.log(&format!(">> Request: {} {}", request.method, request.path));

        if self.config.log_request_headers {
            self.log(&format!(">> Headers:\n{}", self.format_headers(&request.headers)));
        }

        if self.config.log_request_body && !request.body.is_empty() {
            self.log(&format!(">> Body:\n{}", self.format_body(&request.body)));
        }

        // Store the start time in the request context
        match request.context.write().await {
            mut context => {
                context.start_time = Some(Instant::now());
            }
        }

        Ok(request)
    }

    async fn post_filter(&self, request: ProxyRequest, response: ProxyResponse) -> Result<ProxyResponse, ProxyError> {
        self.log(&format!("<< Response: {} {} (Status: {})", request.method, request.path, response.status));

        // Calculate and log the request duration if we have start time
        match request.context.read().await {
            request_context => {
                if let Some(start_time) = request_context.start_time {
                    let duration = start_time.elapsed();
                    self.log(&format!("<< Duration: {:?}", duration));
                }
            }
        }

        if self.config.log_response_headers {
            self.log(&format!("<< Headers:\n{}", self.format_headers(&response.headers)));
        }

        if self.config.log_response_body && !response.body.is_empty() {
            self.log(&format!("<< Body:\n{}", self.format_body(&response.body)));
        }

        Ok(response)
    }
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
    pub fn new(config: PathRewriteFilterConfig) -> Self {
        // Compile the regex
        let regex = Regex::new(&config.pattern)
            .expect("Failed to compile path rewrite pattern");

        Self { config, regex }
    }

    /// Create a new path rewrite filter with default configuration.
    pub fn default() -> Self {
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
            let rewritten_path = self.regex.replace_all(&request.path, &self.config.replacement).to_string();

            if rewritten_path != request.path {
                debug!("Rewriting path from {} to {}", request.path, rewritten_path);
                request.path = rewritten_path;
            }
        }

        Ok(request)
    }

    async fn post_filter(&self, _request: ProxyRequest, response: ProxyResponse) -> Result<ProxyResponse, ProxyError> {
        // For now, we don't implement response path rewriting 
        // as it would require parsing and modifying the response body
        // which is complex and content-type dependent

        Ok(response)
    }
}

/// Factory for creating filters based on configuration.
#[derive(Debug)]
pub struct FilterFactory;

impl FilterFactory {
    /// Create a filter based on the filter type and configuration.
    pub fn create_filter(filter_type: &str, config: serde_json::Value) -> Result<Arc<dyn Filter>, ProxyError> {
        match filter_type {
            "logging" => {
                let config: LoggingFilterConfig = serde_json::from_value(config)
                    .map_err(|e| ProxyError::FilterError(format!("Invalid logging filter config: {}", e)))?;
                Ok(Arc::new(LoggingFilter::new(config)))
            },
            "header" => {
                let config: HeaderFilterConfig = serde_json::from_value(config)
                    .map_err(|e| ProxyError::FilterError(format!("Invalid header filter config: {}", e)))?;
                Ok(Arc::new(HeaderFilter::new(config)))
            },
            "timeout" => {
                let config: TimeoutFilterConfig = serde_json::from_value(config)
                    .map_err(|e| ProxyError::FilterError(format!("Invalid timeout filter config: {}", e)))?;
                Ok(Arc::new(TimeoutFilter::new(config)))
            },
            "path_rewrite" => {
                let config: PathRewriteFilterConfig = serde_json::from_value(config)
                    .map_err(|e| ProxyError::FilterError(format!("Invalid path rewrite filter config: {}", e)))?;
                Ok(Arc::new(PathRewriteFilter::new(config)))
            },
            _ => Err(ProxyError::FilterError(format!("Unknown filter type: {}", filter_type))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::HttpMethod;
    use crate::RequestContext;

    #[tokio::test]
    async fn test_logging_filter() {
        // Create a test request
        let request = ProxyRequest {
            method: HttpMethod::Get,
            path: "/test".to_string(),
            query: None,
            headers: {
                let mut map = reqwest::header::HeaderMap::new();
                map.insert(
                    reqwest::header::HeaderName::from_static("content-type"),
                    reqwest::header::HeaderValue::from_static("application/json"),
                );
                map
            },
            body: b"{\"test\": \"value\"}".to_vec(),
            context: Arc::new(tokio::sync::RwLock::new(RequestContext::default())),
        };

        // Create a logging filter
        let config = LoggingFilterConfig {
            log_request_body: true,
            ..LoggingFilterConfig::default()
        };
        let filter = LoggingFilter::new(config);

        // Apply the filter
        let filtered_request = filter.pre_filter(request).await.unwrap();

        // Verify that the start time was set
        let context = filtered_request.context.read().await;
        assert!(context.start_time.is_some());
    }

    #[tokio::test]
    async fn test_header_filter() {
        // Create a test request
        let request = ProxyRequest {
            method: HttpMethod::Get,
            path: "/test".to_string(),
            query: None,
            headers: {
                let mut map = reqwest::header::HeaderMap::new();
                map.insert(
                    reqwest::header::HeaderName::from_static("content-type"),
                    reqwest::header::HeaderValue::from_static("application/json"),
                );
                map.insert(
                    reqwest::header::HeaderName::from_static("x-remove-me"),
                    reqwest::header::HeaderValue::from_static("should be removed"),
                );
                map
            },
            body: Vec::new(),
            context: Arc::new(tokio::sync::RwLock::new(RequestContext::default())),
        };

        // Create a header filter
        let mut config = HeaderFilterConfig::default();
        config.add_request_headers.insert("x-custom-header".to_string(), "custom-value".to_string());
        config.remove_request_headers.push("x-remove-me".to_string());

        let filter = HeaderFilter::new(config);

        // Apply the filter
        let filtered_request = filter.pre_filter(request).await.unwrap();

        // Verify headers were modified
        assert!(filtered_request.headers.contains_key("x-custom-header"));
        assert!(!filtered_request.headers.contains_key("x-remove-me"));

        let custom_header = filtered_request.headers.get("x-custom-header").unwrap();
        assert_eq!(custom_header, "custom-value");
    }

    #[tokio::test]
    async fn test_timeout_filter() {
        // Create a test request
        let request = ProxyRequest {
            method: HttpMethod::Get,
            path: "/test".to_string(),
            query: None,
            headers: reqwest::header::HeaderMap::new(),
            body: Vec::new(),
            context: Arc::new(tokio::sync::RwLock::new(RequestContext::default())),
        };

        // Create a timeout filter
        let config = TimeoutFilterConfig { timeout_ms: 5000 };
        let filter = TimeoutFilter::new(config);

        // Apply the filter
        let filtered_request = filter.pre_filter(request).await.unwrap();

        // Verify timeout was set in context
        let context = filtered_request.context.read().await;
        let timeout = context.attributes.get("timeout_ms").unwrap();
        assert_eq!(timeout, &serde_json::json!(5000));
    }
}