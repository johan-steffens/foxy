// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Basic authentication provider.

use crate::{
    core::{ProxyError, ProxyRequest},
    debug_fmt, error_fmt,
    security::{SecurityProvider, SecurityStage},
    trace_fmt, warn_fmt,
};
use async_trait::async_trait;
use base64::{Engine as _, engine::general_purpose};
use globset::{Glob, GlobSet, GlobSetBuilder};
use serde::Deserialize;
use subtle::ConstantTimeEq;

const BASIC: &str = "basic ";

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
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
        let method_match = self.methods.iter().any(|m| m == "*" || m == method);
        let path_match = self.paths.is_match(path);

        trace_fmt!(
            "BasicAuthProvider",
            "Basic Auth bypass rule check: method={} path={} -> method_match={} path_match={}",
            method,
            path,
            method_match,
            path_match
        );

        method_match && path_match
    }
}

/// Configuration for the Basic Auth provider.
#[derive(Debug, Clone, Deserialize, serde::Serialize)]
pub struct BasicAuthConfig {
    /// List of valid username:password pairs.
    pub credentials: Vec<String>,
    /// Routes to bypass authentication for.
    #[serde(default)]
    pub bypass: Vec<RouteRuleConfig>,
}

/// Basic authentication security provider.
#[derive(Debug)]
pub struct BasicAuthProvider {
    valid_credentials: Vec<(String, String)>,
    rules: Vec<RouteRule>,
}

impl BasicAuthProvider {
    pub fn new(cfg: BasicAuthConfig) -> Result<Self, ProxyError> {
        let mut valid_credentials = Vec::new();
        for cred_pair in cfg.credentials {
            let parts: Vec<&str> = cred_pair.splitn(2, ':').collect();
            if parts.len() == 2 {
                valid_credentials.push((parts[0].to_string(), parts[1].to_string()));
            } else {
                let err =
                    ProxyError::SecurityError(format!("Invalid credential format: {cred_pair}"));
                error_fmt!("BasicAuthProvider", "{}", err);
                return Err(err);
            }
        }

        let mut rules = Vec::with_capacity(cfg.bypass.len());
        for raw in cfg.bypass {
            let mut builder = GlobSetBuilder::new();
            match Glob::new(&raw.path) {
                Ok(glob) => {
                    builder.add(glob);
                    rules.push(RouteRule {
                        methods: raw.methods.iter().map(|m| m.to_ascii_uppercase()).collect(),
                        paths: match builder.build() {
                            Ok(set) => set,
                            Err(e) => {
                                let err = ProxyError::SecurityError(format!(
                                    "Failed to build glob set for path {}: {}",
                                    raw.path, e
                                ));
                                error_fmt!("BasicAuthProvider", "{}", err);
                                return Err(err);
                            }
                        },
                    });
                    debug_fmt!(
                        "BasicAuthProvider",
                        "Added Basic Auth bypass rule: methods={:?}, path={}",
                        raw.methods,
                        raw.path
                    );
                }
                Err(e) => {
                    let err = ProxyError::SecurityError(format!(
                        "Invalid glob pattern in bypass rule: {e}"
                    ));
                    error_fmt!("BasicAuthProvider", "{}", err);
                    return Err(err);
                }
            }
        }

        Ok(Self {
            valid_credentials,
            rules,
        })
    }

    /// Validate credentials using constant-time comparison to prevent timing attacks.
    ///
    /// This method performs constant-time comparison of both username and password
    /// to prevent timing-based username enumeration attacks.
    pub fn validate_credentials_constant_time(&self, username: &str, password: &str) -> bool {
        let mut valid = false;

        // SECURITY: Always check against all credentials to maintain constant time
        // This prevents timing attacks that could enumerate valid usernames
        for (stored_username, stored_password) in &self.valid_credentials {
            let username_match = stored_username.as_bytes().ct_eq(username.as_bytes());
            let password_match = stored_password.as_bytes().ct_eq(password.as_bytes());

            // Use constant-time AND operation
            let both_match = username_match & password_match;

            // Use constant-time OR to accumulate the result
            valid |= bool::from(both_match);
        }

        valid
    }

    #[inline]
    fn is_bypassed(&self, method: &str, path: &str) -> bool {
        let bypassed = self.rules.iter().any(|r| r.matches(method, path));
        if bypassed {
            debug_fmt!(
                "BasicAuthProvider",
                "Basic Auth bypass for {} {}",
                method,
                path
            );
        }
        bypassed
    }
}

#[async_trait]
impl SecurityProvider for BasicAuthProvider {
    fn name(&self) -> &str {
        "Basic"
    }

    fn stage(&self) -> SecurityStage {
        SecurityStage::Pre
    }

    async fn pre(&self, req: ProxyRequest) -> Result<ProxyRequest, ProxyError> {
        // 0) Bypass?
        if self.is_bypassed(&req.method.to_string(), &req.path) {
            debug_fmt!(
                "BasicAuthProvider",
                "Basic Auth bypass for {} {}",
                req.method,
                req.path
            );
            return Ok(req);
        }

        debug_fmt!(
            "BasicAuthProvider",
            "Basic Auth validating request: {} {}",
            req.method,
            req.path
        );

        // 1) Extract Authorization header
        let auth_header = match req.headers.get("authorization") {
            Some(h) => match h.to_str() {
                Ok(s) => s,
                Err(e) => {
                    let err =
                        ProxyError::SecurityError(format!("Invalid authorization header: {e}"));
                    warn_fmt!("BasicAuthProvider", "{}", err);
                    return Err(err);
                }
            },
            None => {
                let err = ProxyError::SecurityError("Missing authorization header".to_string());
                warn_fmt!("BasicAuthProvider", "{}", err);
                return Err(err);
            }
        };

        if !auth_header.to_lowercase().starts_with(BASIC) {
            let err = ProxyError::SecurityError(format!(
                "Invalid authorization scheme: expected 'Basic', got '{}'",
                auth_header.split_whitespace().next().unwrap_or("")
            ));
            warn_fmt!("BasicAuthProvider", "{}", err);
            return Err(err);
        }

        let encoded_credentials = &auth_header[BASIC.len()..];
        if encoded_credentials.is_empty() {
            let err = ProxyError::SecurityError("Empty basic auth credentials".to_string());
            warn_fmt!("BasicAuthProvider", "{}", err);
            return Err(err);
        }

        // 2) Decode credentials
        let decoded_credentials = match general_purpose::STANDARD.decode(encoded_credentials) {
            Ok(bytes) => match String::from_utf8(bytes) {
                Ok(s) => s,
                Err(e) => {
                    let err =
                        ProxyError::SecurityError(format!("Invalid UTF-8 in credentials: {e}"));
                    warn_fmt!("BasicAuthProvider", "{}", err);
                    return Err(err);
                }
            },
            Err(e) => {
                let err =
                    ProxyError::SecurityError(format!("Failed to base64 decode credentials: {e}"));
                warn_fmt!("BasicAuthProvider", "{}", err);
                return Err(err);
            }
        };

        let parts: Vec<&str> = decoded_credentials.splitn(2, ':').collect();
        if parts.len() != 2 {
            let err = ProxyError::SecurityError("Invalid basic auth credential format".to_string());
            warn_fmt!("BasicAuthProvider", "{}", err);
            return Err(err);
        }
        let username = parts[0];
        let password = parts[1];

        // 3) Validate credentials using constant-time comparison
        // SECURITY: Use constant-time comparison to prevent timing attacks
        if self.validate_credentials_constant_time(username, password) {
            debug_fmt!(
                "BasicAuthProvider",
                "Basic Auth validation successful for user: {}",
                username
            );
            Ok(req)
        } else {
            let err = ProxyError::SecurityError("Invalid basic auth credentials".to_string());
            warn_fmt!("BasicAuthProvider", "{}", err);
            Err(err)
        }
    }
}
