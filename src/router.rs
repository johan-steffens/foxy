// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Router implementation for Foxy.
//!
//! This module provides the routing functionality for the proxy,
//! determining which target a request should be forwarded to.

use std::collections::HashMap;
use std::sync::Arc;
use async_trait::async_trait;
use tokio::sync::RwLock;
use regex::Regex;
use serde::{Serialize, Deserialize};

use crate::config::Config;
use crate::core::{ProxyRequest, ProxyError, Router, Route};

/// Configuration for a route.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouteConfig {
    /// The ID of the route (for logging and reference)
    pub id: String,
    /// The base URL of the target
    pub target: String,
    /// The path pattern that this route matches
    pub path: String,
    /// The filter IDs that should be applied to this route
    #[serde(default)]
    pub filters: Vec<String>,
    /// Priority of the route (higher means higher priority)
    #[serde(default = "default_priority")]
    pub priority: i32,
}

fn default_priority() -> i32 {
    0
}

/// A simple router implementation based on path patterns.
#[derive(Debug)]
pub struct PathRouter {
    /// Routes managed by this router, stored by ID
    routes: RwLock<HashMap<String, Route>>,
    /// Compiled regular expressions for route matching
    patterns: RwLock<Vec<(Regex, Route)>>,
    /// Configuration for the router
    config: Arc<Config>,
}

impl PathRouter {
    /// Create a new path router with the given configuration.
    pub async fn new(config: Arc<Config>) -> Result<Self, ProxyError> {
        let router = Self {
            routes: RwLock::new(HashMap::new()),
            patterns: RwLock::new(Vec::new()),
            config,
        };

        // Initialize routes from configuration
        router.load_routes_from_config().await?;

        Ok(router)
    }

    /// Load routes from the configuration.
    async fn load_routes_from_config(&self) -> Result<(), ProxyError> {
        // Get routes from configuration
        let route_configs: Option<Vec<RouteConfig>> = self.config.get("routes")?;

        if let Some(route_configs) = route_configs {
            // Sort routes by priority (higher priority first)
            let mut sorted_routes = route_configs;
            sorted_routes.sort_by(|a, b| b.priority.cmp(&a.priority));

            // Add each route
            for route_config in sorted_routes {
                let route = Route {
                    id: route_config.id,
                    target_base_url: route_config.target,
                    path_pattern: route_config.path,
                    filter_ids: route_config.filters,
                };

                self.add_route(route).await?;
            }
        }

        // If no routes are configured, add a default route if a default target is configured
        if self.routes.read().await.is_empty() {
            if let Ok(Some(default_target)) = self.config.get::<String>("proxy.default_target") {
                let default_route = Route {
                    id: "default".to_string(),
                    target_base_url: default_target,
                    path_pattern: ".*".to_string(),  // Match any path
                    filter_ids: Vec::new(),
                };

                self.add_route(default_route).await?;
            }
        }

        Ok(())
    }

    /// Compile a path pattern into a regular expression.
    fn compile_pattern(&self, pattern: &str) -> Result<Regex, ProxyError> {
        // Escape the pattern for use in a regex
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
                    regex_pattern.push_str(&format!("([^/]+)"));
                },
                // Handle wildcards like *
                '*' => {
                    regex_pattern.push_str("(.*)");
                },
                // Escape special regex characters
                '.' | '^' | '$' | '|' | '+' | '?' | '(' | ')' | '[' | ']' | '{' | '}' | '\\' => {
                    regex_pattern.push('\\');
                    regex_pattern.push(c);
                },
                // Regular characters
                _ => {
                    regex_pattern.push(c);
                }
            }
        }

        regex_pattern.push('$');

        Regex::new(&regex_pattern)
            .map_err(|e| ProxyError::RoutingError(format!("Invalid route pattern '{}': {}", pattern, e)))
    }
}

#[async_trait]
impl Router for PathRouter {
    async fn route(&self, request: &ProxyRequest) -> Result<Route, ProxyError> {
        let path = &request.path;

        // Try to find a matching route
        let patterns = self.patterns.read().await;

        for (regex, route) in patterns.iter() {
            if regex.is_match(path) {
                return Ok(route.clone());
            }
        }

        // If no route is found, try to use a default route if configured
        if let Ok(Some(default_target)) = self.config.get::<String>("proxy.default_target") {
            return Ok(Route {
                id: "default".to_string(),
                target_base_url: default_target,
                path_pattern: ".*".to_string(),
                filter_ids: Vec::new(),
            });
        }

        // No route found
        Err(ProxyError::RoutingError(format!("No route found for path: {}", path)))
    }

    async fn get_routes(&self) -> Vec<Route> {
        self.routes.read().await.values().cloned().collect()
    }

    async fn add_route(&self, route: Route) -> Result<(), ProxyError> {
        // Compile the pattern into a regex
        let regex = self.compile_pattern(&route.path_pattern)?;

        // Store the route
        {
            let mut routes = self.routes.write().await;
            routes.insert(route.id.clone(), route.clone());
        }

        // Add the compiled pattern
        {
            let mut patterns = self.patterns.write().await;
            patterns.push((regex, route));

            // Sort patterns by specificity (more specific first)
            // This is a simple heuristic: patterns with more characters are considered more specific
            patterns.sort_by(|(_, a), (_, b)| {
                b.path_pattern.len().cmp(&a.path_pattern.len())
            });
        }

        Ok(())
    }

    async fn remove_route(&self, route_id: &str) -> Result<(), ProxyError> {
        // Remove the route from the routes map
        {
            let mut routes = self.routes.write().await;
            if routes.remove(route_id).is_none() {
                return Err(ProxyError::RoutingError(format!("Route not found: {}", route_id)));
            }
        }

        // Remove the route from the patterns list
        {
            let mut patterns = self.patterns.write().await;
            patterns.retain(|(_, route)| route.id != route_id);
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Config, ConfigProvider};
    use serde_json::{json, Value};

    #[derive(Debug)]
    struct MockConfigProvider {
        routes: Vec<RouteConfig>,
    }

    impl ConfigProvider for MockConfigProvider {
        fn get_raw(&self, key: &str) -> Result<Option<Value>, crate::config::ConfigError> {
            if key == "routes" {
                Ok(Some(json!(self.routes)))
            } else if key == "proxy.default_target" {
                Ok(Some(json!("http://default-target.com")))
            } else {
                Ok(None)
            }
        }

        fn has(&self, key: &str) -> bool {
            key == "routes" || key == "proxy.default_target"
        }

        fn provider_name(&self) -> &str {
            "mock_provider"
        }
    }

    #[tokio::test]
    async fn test_route_matching() {
        let routes = vec![
            RouteConfig {
                id: "api".to_string(),
                target: "http://api-service.com".to_string(),
                path: "/api/:version/*".to_string(),
                filters: vec!["logging".to_string()],
                priority: 10,
            },
            RouteConfig {
                id: "web".to_string(),
                target: "http://web-service.com".to_string(),
                path: "/*".to_string(),
                filters: vec![],
                priority: 0,
            },
        ];

        let provider = MockConfigProvider { routes };
        let config = Config::builder().with_provider(provider).build();
        let router = PathRouter::new(Arc::new(config)).await.unwrap();

        // Test API route
        let api_request = ProxyRequest {
            method: crate::core::HttpMethod::Get,
            path: "/api/v1/users".to_string(),
            query: None,
            headers: reqwest::header::HeaderMap::new(),
            body: Vec::new(),
            context: Arc::new(RwLock::new(crate::core::RequestContext::default())),
        };

        let api_route = router.route(&api_request).await.unwrap();
        assert_eq!(api_route.id, "api");
        assert_eq!(api_route.target_base_url, "http://api-service.com");

        // Test web route
        let web_request = ProxyRequest {
            method: crate::core::HttpMethod::Get,
            path: "/home".to_string(),
            query: None,
            headers: reqwest::header::HeaderMap::new(),
            body: Vec::new(),
            context: Arc::new(RwLock::new(crate::core::RequestContext::default())),
        };

        let web_route = router.route(&web_request).await.unwrap();
        assert_eq!(web_route.id, "web");
        assert_eq!(web_route.target_base_url, "http://web-service.com");
    }

    #[tokio::test]
    async fn test_default_route() {
        // Create a config with no routes
        let provider = MockConfigProvider { routes: vec![] };
        let config = Config::builder().with_provider(provider).build();
        let router = PathRouter::new(Arc::new(config)).await.unwrap();

        // Test that the default route is used
        let request = ProxyRequest {
            method: crate::core::HttpMethod::Get,
            path: "/some/path".to_string(),
            query: None,
            headers: reqwest::header::HeaderMap::new(),
            body: Vec::new(),
            context: Arc::new(RwLock::new(crate::core::RequestContext::default())),
        };

        let route = router.route(&request).await.unwrap();
        assert_eq!(route.id, "default");
        assert_eq!(route.target_base_url, "http://default-target.com");
    }
}