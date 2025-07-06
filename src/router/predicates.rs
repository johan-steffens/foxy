// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Predicate implementations for router matching.
//!
//! This module provides various predicates that can be used for route matching.

use async_trait::async_trait;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use super::Predicate;
use crate::core::{HttpMethod, ProxyError, ProxyRequest};
use crate::warn_fmt;

/// Configuration for a path predicate.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PathPredicateConfig {
    /// The path pattern to match
    pub pattern: String,
}

/// A predicate that matches on request path.
#[derive(Debug)]
pub struct PathPredicate {
    /// The configuration for this predicate
    #[allow(dead_code)]
    config: PathPredicateConfig,
    /// Compiled regex for path matching
    regex: Regex,
}

impl PathPredicate {
    /// Create a new path predicate with the given configuration.
    pub fn new(config: PathPredicateConfig) -> Result<Self, ProxyError> {
        // Convert the path pattern to a regex
        let regex_pattern = Self::pattern_to_regex(&config.pattern);

        // Compile the regex
        let regex = Regex::new(&regex_pattern).map_err(|e| {
            ProxyError::RoutingError(format!(
                "Invalid path predicate regex pattern '{}': {}",
                config.pattern, e
            ))
        })?;

        Ok(Self { config, regex })
    }

    /// Convert a path pattern to a regex pattern.
    fn pattern_to_regex(pattern: &str) -> String {
        let mut regex_pattern = "^".to_string();

        let mut chars = pattern.chars().peekable();
        while let Some(c) = chars.next() {
            match c {
                // Handle path parameters like :id
                ':' => {
                    let mut param_name = String::new();
                    while let Some(&next_char) = chars.peek() {
                        if next_char.is_alphanumeric() || next_char == '_' {
                            param_name.push(chars.next().unwrap());
                        } else {
                            break;
                        }
                    }

                    // Add a capturing group for the parameter
                    regex_pattern.push_str("([^/]+)");
                }
                // Handle wildcards like *
                '*' => {
                    regex_pattern.push_str("(.*)");
                }
                // Escape special regex characters
                '.' | '^' | '$' | '|' | '+' | '?' | '(' | ')' | '[' | ']' | '{' | '}' | '\\' => {
                    regex_pattern.push('\\');
                    regex_pattern.push(c);
                }
                // Regular characters
                _ => {
                    regex_pattern.push(c);
                }
            }
        }

        regex_pattern.push('$');
        regex_pattern
    }
}

#[async_trait]
impl Predicate for PathPredicate {
    async fn matches(&self, request: &ProxyRequest) -> bool {
        self.regex.is_match(&request.path)
    }

    fn predicate_type(&self) -> &str {
        "path"
    }
}

/// Configuration for a method predicate.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MethodPredicateConfig {
    /// The HTTP methods to match
    pub methods: Vec<HttpMethod>,
}

/// A predicate that matches on HTTP method.
#[derive(Debug)]
pub struct MethodPredicate {
    /// The configuration for this predicate
    config: MethodPredicateConfig,
}

impl MethodPredicate {
    /// Create a new method predicate with the given configuration.
    pub fn new(config: MethodPredicateConfig) -> Self {
        Self { config }
    }
}

#[async_trait]
impl Predicate for MethodPredicate {
    async fn matches(&self, request: &ProxyRequest) -> bool {
        self.config.methods.contains(&request.method)
    }

    fn predicate_type(&self) -> &str {
        "method"
    }
}

/// Configuration for a header predicate.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeaderPredicateConfig {
    /// The headers to match (name and value)
    pub headers: HashMap<String, String>,
    /// Whether to require exact match for header values
    #[serde(default)]
    pub exact_match: bool,
}

/// A predicate that matches on request headers.
#[derive(Debug)]
pub struct HeaderPredicate {
    /// The configuration for this predicate
    config: HeaderPredicateConfig,
}

impl HeaderPredicate {
    /// Create a new header predicate with the given configuration.
    pub fn new(config: HeaderPredicateConfig) -> Self {
        Self { config }
    }
}

#[async_trait]
impl Predicate for HeaderPredicate {
    async fn matches(&self, request: &ProxyRequest) -> bool {
        for (name, expected_value) in &self.config.headers {
            // Try to get the header
            if let Some(header_value) = request.headers.get(name) {
                // Convert to string for comparison
                if let Ok(actual_value) = header_value.to_str() {
                    if self.config.exact_match {
                        // Exact match
                        if actual_value != expected_value {
                            return false;
                        }
                    } else {
                        // Contains match
                        if !actual_value.contains(expected_value) {
                            return false;
                        }
                    }
                } else {
                    // Not a valid UTF-8 string
                    return false;
                }
            } else {
                // Header not found
                return false;
            }
        }

        // All headers matched
        true
    }

    fn predicate_type(&self) -> &str {
        "header"
    }
}

/// Configuration for a query parameter predicate.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryPredicateConfig {
    /// The query parameters to match (name and value)
    pub params: HashMap<String, String>,
    /// Whether to require exact match for parameter values
    #[serde(default)]
    pub exact_match: bool,
}

/// A predicate that matches on query parameters.
#[derive(Debug)]
pub struct QueryPredicate {
    /// The configuration for this predicate
    config: QueryPredicateConfig,
}

impl QueryPredicate {
    /// Create a new query predicate with the given configuration.
    pub fn new(config: QueryPredicateConfig) -> Self {
        Self { config }
    }

    /// Validate and sanitize a query parameter value to prevent injection attacks.
    ///
    /// This function checks for dangerous patterns that could be used in various
    /// injection attacks and logs warnings when suspicious content is detected.
    fn validate_query_value(key: &str, value: &str) -> String {
        let mut sanitized = value.to_string();
        let mut warnings = Vec::new();

        // SECURITY: Check for CRLF injection patterns
        if value.contains('\r') || value.contains('\n') {
            warnings.push("CRLF injection");
            sanitized = sanitized.replace(['\r', '\n'], "");
        }

        // SECURITY: Check for path traversal patterns
        if value.contains("../") || value.contains("..\\") {
            warnings.push("path traversal");
        }

        // SECURITY: Check for XSS patterns
        let xss_patterns = ["<script", "javascript:", "onload=", "onerror=", "onclick="];
        for pattern in &xss_patterns {
            if value.to_lowercase().contains(pattern) {
                warnings.push("potential XSS");
                break;
            }
        }

        // SECURITY: Check for SQL injection patterns
        let sql_patterns = [
            "union select",
            "drop table",
            "insert into",
            "delete from",
            "'or'1'='1",
        ];
        for pattern in &sql_patterns {
            if value.to_lowercase().contains(pattern) {
                warnings.push("potential SQL injection");
                break;
            }
        }

        // SECURITY: Check for command injection patterns
        let cmd_patterns = [";", "|", "&", "`", "$", "$("];
        for pattern in &cmd_patterns {
            if value.contains(pattern) {
                warnings.push("potential command injection");
                break;
            }
        }

        // SECURITY: Check for null byte injection
        if value.contains('\0') {
            warnings.push("null byte injection");
            sanitized = sanitized.replace('\0', "");
        }

        // Log warnings for suspicious patterns
        if !warnings.is_empty() {
            warn_fmt!(
                "QueryPredicate",
                "Suspicious query parameter detected - key: '{}', value: '{}', patterns: [{}]",
                key,
                value,
                warnings.join(", ")
            );
        }

        sanitized
    }

    /// Parse query parameters from a query string with input validation.
    fn parse_query_params(query: &str) -> HashMap<String, String> {
        let mut params = HashMap::new();

        // SECURITY: Limit query string length to prevent DoS
        const MAX_QUERY_LENGTH: usize = 8192;
        if query.len() > MAX_QUERY_LENGTH {
            warn_fmt!(
                "QueryPredicate",
                "Query string too long: {} bytes (max: {})",
                query.len(),
                MAX_QUERY_LENGTH
            );
            return params;
        }

        for pair in query.split('&') {
            let mut iter = pair.split('=');
            if let (Some(key), Some(value)) = (iter.next(), iter.next()) {
                // SECURITY: URL decode the key and value
                let decoded_key = urlencoding::decode(key).unwrap_or_else(|_| {
                    warn_fmt!("QueryPredicate", "Failed to URL decode key: {}", key);
                    key.into()
                });
                let decoded_value = urlencoding::decode(value).unwrap_or_else(|_| {
                    warn_fmt!("QueryPredicate", "Failed to URL decode value: {}", value);
                    value.into()
                });

                // SECURITY: Validate and sanitize the parameter value
                let sanitized_value = Self::validate_query_value(&decoded_key, &decoded_value);

                params.insert(decoded_key.to_string(), sanitized_value);
            }
        }

        params
    }
}

#[async_trait]
impl Predicate for QueryPredicate {
    async fn matches(&self, request: &ProxyRequest) -> bool {
        // If no query parameters to match, then it's a match
        if self.config.params.is_empty() {
            return true;
        }

        // If the request has no query string, it's not a match
        if let Some(query) = &request.query {
            let params = Self::parse_query_params(query);

            for (name, expected_value) in &self.config.params {
                // Try to get the parameter
                if let Some(actual_value) = params.get(name) {
                    if self.config.exact_match {
                        // Exact match
                        if actual_value != expected_value {
                            return false;
                        }
                    } else {
                        // Contains match
                        if !actual_value.contains(expected_value) {
                            return false;
                        }
                    }
                } else {
                    // Parameter not found
                    return false;
                }
            }

            // All parameters matched
            true
        } else {
            false
        }
    }

    fn predicate_type(&self) -> &str {
        "query"
    }
}
