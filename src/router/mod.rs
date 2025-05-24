// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Routing DSL – *predicates* & helper logic.
//!
//! A [`PredicateRouter`] owns an ordered vector of [`Route`]s.  
//! The first route whose **predicate stack** returns `true` wins and its
//! filter-chain is executed.
//!
//! ### Built-in predicates
//! | type              | configuration key     | example                              |
//! |-------------------|-----------------------|--------------------------------------|
//! | `MethodPredicate` | `method`              | `"GET"`                              |
//! | `PathPredicate`   | `path` (regex)        | `"/api/v1/.*"`                       |
//! | `HeaderPredicate` | `header.<NAME>`       | `"X-Request-Id" = "^[0-9a-f-]{36}$"` |
//! | `QueryPredicate`  | `query.<NAME>`        | `"tenant"` = `"acme-corp"`           |

mod predicates;

#[cfg(test)]
mod tests;

pub use predicates::*;

use std::collections::HashMap;
use std::sync::Arc;
use async_trait::async_trait;
use tokio::sync::RwLock;
use serde::{Serialize, Deserialize};

use crate::config::Config;
use crate::core::{ProxyRequest, ProxyError, Route};
use crate::FilterFactory;

/// Configuration for a route.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouteConfig {
    /// The ID of the route (for logging and reference)
    pub id: String,
    /// The base URL of the target
    pub target: String,
    /// Filters to apply to this route
    #[serde(default)]
    pub filters: Vec<FilterConfig>,
    /// Priority of the route (higher means higher priority)
    #[serde(default = "default_priority")]
    pub priority: i32,
    /// Predicates for this route
    #[serde(default)]
    pub predicates: Vec<PredicateConfig>,
}

/// Configuration for a filter.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FilterConfig {
    /// The type of filter
    #[serde(rename = "type")]
    pub type_: String,
    /// The configuration for the filter
    pub config: serde_json::Value,
}

fn default_priority() -> i32 {
    0
}

/// Configuration for a predicate.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PredicateConfig {
    /// The type of predicate
    pub type_: String,
    /// The configuration for the predicate
    pub config: serde_json::Value,
}

/// A predicate that determines if a request matches a route.
#[async_trait]
pub trait Predicate: Send + Sync + std::fmt::Debug {
    /// Check if the request matches this predicate.
    async fn matches(&self, request: &ProxyRequest) -> bool;

    /// Get the predicate type.
    fn predicate_type(&self) -> &str;
}

/// The predicable router implementation.
#[derive(Debug)]
pub struct PredicateRouter {
    /// Routes managed by this router, stored by ID
    routes: RwLock<HashMap<String, RouteWithPredicates>>,
    /// Sorted list of routes by priority
    sorted_routes: RwLock<Vec<RouteWithPredicates>>,
    /// Configuration for the router
    config: Arc<Config>,
}

/// A route with associated predicates.
#[derive(Debug, Clone)]
struct RouteWithPredicates {
    /// The route
    route: Route,
    /// Predicates that must match for this route
    predicates: Vec<Arc<dyn Predicate>>,
    /// Priority of the route
    priority: i32,
}

impl PredicateRouter {
    /// Create a new predicate router with the given configuration.
    pub async fn new(config: Arc<Config>) -> Result<Self, ProxyError> {
        let router = Self {
            routes: RwLock::new(HashMap::new()),
            sorted_routes: RwLock::new(Vec::new()),
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
            // Add each route
            for route_config in route_configs {
                // Create predicates for this route
                let mut predicates = Vec::new();
                for predicate_config in &route_config.predicates {
                    let predicate = PredicateFactory::create_predicate(
                        &predicate_config.type_,
                        predicate_config.config.clone(),
                    )?;
                    predicates.push(predicate);
                }

                // Create filters for this route
                let mut filters = Vec::new();
                for filter_config in &route_config.filters {
                    let filter = FilterFactory::create_filter(
                        &filter_config.type_,
                        filter_config.config.clone(),
                    )?;
                    filters.push(filter);
                }

                // Find the first path predicate to use as the route pattern
                let path_pattern = route_config.predicates.iter()
                    .find(|p| p.type_ == "path")
                    .map(|p| p.config.get("pattern")
                        .and_then(|v| v.as_str())
                        .unwrap_or("/*"))
                    .unwrap_or("/*")
                    .to_string();

                let route = Route {
                    id: route_config.id.clone(),
                    target_base_url: route_config.target.clone(),
                    path_pattern,
                    filters: if filters.is_empty() { None } else { Some(filters) },
                };

                // Add the route with its predicates
                self.add_route_with_predicates(
                    route,
                    predicates,
                    route_config.priority,
                ).await?;
            }
        }

        Ok(())
    }

    /// Add a route with predicates and priority.
    async fn add_route_with_predicates(
        &self,
        route: Route,
        predicates: Vec<Arc<dyn Predicate>>,
        priority: i32,
    ) -> Result<(), ProxyError> {
        let route_with_predicates = RouteWithPredicates {
            route: route.clone(),
            predicates,
            priority,
        };

        // Store the route
        {
            let mut routes = self.routes.write().await;
            routes.insert(route.id.clone(), route_with_predicates.clone());
        }

        // Update sorted routes
        {
            let mut sorted_routes = self.sorted_routes.write().await;
            sorted_routes.push(route_with_predicates);

            // Sort by priority (higher first)
            sorted_routes.sort_by(|a, b| b.priority.cmp(&a.priority));
        }

        Ok(())
    }
}

#[async_trait]
impl crate::core::Router for PredicateRouter {
    async fn route(&self, request: &ProxyRequest) -> Result<Route, ProxyError> {
        // Find the first route where all predicates match
        let sorted_routes = self.sorted_routes.read().await;
        log::trace!("Routing request {} {} against {} routes", 
            request.method, request.path, sorted_routes.len());

        for route_with_predicates in sorted_routes.iter() {
            // Check all predicates for this route
            let mut all_match = true;
            let route_id = &route_with_predicates.route.id;
            
            log::trace!("Checking route '{}' with {} predicates", 
                route_id, route_with_predicates.predicates.len());

            for predicate in &route_with_predicates.predicates {
                let predicate_type = predicate.predicate_type();
                let matches = predicate.matches(request).await;
                
                log::trace!("  Predicate '{}' for route '{}': {}", 
                    predicate_type, route_id, if matches { "match" } else { "no match" });
                
                if !matches {
                    all_match = false;
                    break;
                }
            }

            // If all predicates match, use this route
            if all_match {
                log::debug!("Route '{}' matched request {} {}", 
                    route_id, request.method, request.path);
                return Ok(route_with_predicates.route.clone());
            }
        }

        // No route matched
        let err = ProxyError::RoutingError(format!("No route matched the request: {} {}",
                                             request.method, request.path));
        log::warn!("{}", err);
        Err(err)
    }

    async fn get_routes(&self) -> Vec<Route> {
        let routes = self.routes.read().await;
        routes.values().map(|r| r.route.clone()).collect()
    }

    async fn add_route(&self, route: Route) -> Result<(), ProxyError> {
        // Create an empty predicate list - this is not the recommended way to add routes
        // Users should use add_route_with_predicates instead
        self.add_route_with_predicates(route, Vec::new(), 0).await
    }

    async fn remove_route(&self, route_id: &str) -> Result<(), ProxyError> {
        // Remove the route from the routes map
        {
            let mut routes = self.routes.write().await;
            if routes.remove(route_id).is_none() {
                return Err(ProxyError::RoutingError(format!("Route not found: {}", route_id)));
            }
        }

        // Remove the route from the sorted list
        {
            let mut sorted_routes = self.sorted_routes.write().await;
            sorted_routes.retain(|r| r.route.id != route_id);
        }

        Ok(())
    }
}

/// Factory for creating predicates based on configuration.
#[derive(Debug)]
pub struct PredicateFactory;

impl PredicateFactory {
    /// Create a predicate based on the predicate type and configuration.
    pub fn create_predicate(
        predicate_type: &str,
        config: serde_json::Value,
    ) -> Result<Arc<dyn Predicate>, ProxyError> {
        log::debug!("Creating predicate of type '{}' with config: {}", 
            predicate_type, config);
            
        match predicate_type {
            "path" => {
                let path_config: PathPredicateConfig = serde_json::from_value(config)
                    .map_err(|e| {
                        let err = ProxyError::RoutingError(
                            format!("Invalid path predicate config: {}", e)
                        );
                        log::error!("{}", err);
                        err
                    })?;
                
                match PathPredicate::new(path_config) { 
                    Ok(predicate) => Ok(Arc::new(predicate)),
                    Err(error) => Err(error),
                }
            },
            "method" => {
                let method_config: MethodPredicateConfig = serde_json::from_value(config)
                    .map_err(|e| {
                        let err = ProxyError::RoutingError(
                            format!("Invalid method predicate config: {}", e)
                        );
                        log::error!("{}", err);
                        err
                    })?;
                Ok(Arc::new(MethodPredicate::new(method_config)))
            },
            "header" => {
                let header_config: HeaderPredicateConfig = serde_json::from_value(config)
                    .map_err(|e| {
                        let err = ProxyError::RoutingError(
                            format!("Invalid header predicate config: {}", e)
                        );
                        log::error!("{}", err);
                        err
                    })?;
                Ok(Arc::new(HeaderPredicate::new(header_config)))
            },
            "query" => {
                let query_config: QueryPredicateConfig = serde_json::from_value(config)
                    .map_err(|e| {
                        let err = ProxyError::RoutingError(
                            format!("Invalid query predicate config: {}", e)
                        );
                        log::error!("{}", err);
                        err
                    })?;
                Ok(Arc::new(QueryPredicate::new(query_config)))
            },
            _ => {
                let err = ProxyError::RoutingError(
                    format!("Unknown predicate type: {}", predicate_type)
                );
                log::error!("{}", err);
                Err(err)
            },
        }
    }
}