// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Foxy - A minimal, configuration-driven, hyper-extendible Rust HTTP proxy library
//!
//! Foxy is designed as a drop-in component with configurable behavior. By default,
//! it provides only basic pass-through routing, with all other functionality
//! requiring explicit opt-in via configuration or code extension.
//!
//! # Core Principles
//!
//! - **Security**: Secure core routing with no features enabled by default
//! - **Extensibility**: Design around traits for user extensions
//! - **Configuration**: Drive all non-default behavior via configuration
//! - **Minimal Default**: "Zero-config" results in only basic request forwarding
//!
//! # Configuration System
//!
//! Foxy's configuration system is built for flexibility and extensibility:
//!
//! - **Multiple Configuration Sources**: Load configuration from files (JSON, TOML, YAML) 
//!   and environment variables.
//! - **Layered Configuration**: Create a hierarchy of configuration providers with 
//!   well-defined priorities.
//! - **Type Safety**: Parse configuration values into the appropriate Rust types.
//! - **Extensibility**: Implement the `ConfigProvider` trait to create custom configuration sources.
//!
//!
//! # Routing and Filtering
//!
//! Foxy uses a configuration-driven approach for routing and filtering.
//!
//! # Custom Filters
//!
//! You can implement custom filters by implementing the `Filter` trait:
//!
//! ```rust,no_run
//! use async_trait::async_trait;
//! use foxy::{Filter, FilterType, ProxyRequest, ProxyResponse, ProxyError};
//!
//! #[derive(Debug)]
//! struct MyCustomFilter;
//!
//! #[async_trait]
//! impl Filter for MyCustomFilter {
//!     fn filter_type(&self) -> FilterType {
//!         FilterType::Both
//!     }
//!
//!     fn name(&self) -> &str {
//!         "my_custom_filter"
//!     }
//!
//!     async fn pre_filter(&self, request: ProxyRequest) -> Result<ProxyRequest, ProxyError> {
//!         // Modify the request
//!         Ok(request)
//!     }
//!
//!     async fn post_filter(&self, request: ProxyRequest, response: ProxyResponse) -> Result<ProxyResponse, ProxyError> {
//!         // Modify the response
//!         Ok(response)
//!     }
//! }
//! ```

// Module declarations
pub mod config;
pub mod loader;
pub mod core;
pub mod router;
pub mod filters;
pub mod server;

// Re-export key types at the crate root for convenience
pub use config::{ConfigProvider, ConfigProviderExt, ConfigError};
pub use loader::{Foxy, FoxyLoader, LoaderError};
pub use core::{
    Filter, FilterType, Router, Route,
    ProxyRequest, ProxyResponse, ProxyError,
    RequestContext, ResponseContext, HttpMethod
};
pub use router::{
    PredicateRouter, Predicate, PredicateFactory,
    PathPredicate, MethodPredicate, HeaderPredicate, QueryPredicate
};
pub use filters::{
    LoggingFilter, HeaderFilter, TimeoutFilter, FilterFactory,
    PathRewriteFilter, PathRewriteFilterConfig
};
pub use server::{ProxyServer, ServerConfig};