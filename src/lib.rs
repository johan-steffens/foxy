// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Foxy - A zero-config, configuration-*driven* HTTP proxy library
//!
//! Foxy offers a *minimal attack-surface* out of the box – it does nothing
//! but forward HTTP/1.1 requests until you deliberately opt-in to extra
//! behaviour via **configuration files** or **extension traits**.
//!
//! ## Quick-start
//!
//! ```bash
//! cargo add foxy-io
//! ```
//!
//! ```rust,no_run
//! use foxy::{Foxy};
//! use std::error::Error;
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn Error>> {
//!     
//!     let foxy = Foxy::loader()
//!         .with_config_file("config.json")
//!         .build().await?;
//!
//!     foxy.start().await?;
//!     Ok(())
//! }
//! ```
//!
//! ## Feature flags
//! | feature | default | description |
//! |---------|---------|-------------|
//! | `opentelemetry` | ❌ | Enables OpenTelemetry tracing integration |
//!
//! ## Extension points
//! * `ConfigProvider` – plug in an arbitrary configuration backend
//! * `Filter`         – inject pre/post processing stages
//! * `Predicate`      – custom routing logic

// Module declarations
pub mod config;
pub mod core;
pub mod filters;
pub mod loader;
pub mod logging;
pub mod opentelemetry;
pub mod router;
pub mod security;
pub mod server;

// Re-export key types at the crate root for convenience
pub use crate::opentelemetry::init;
pub use config::{ConfigError, ConfigProvider, ConfigProviderExt};
pub use core::{
    Filter, FilterType, HttpMethod, ProxyError, ProxyRequest, ProxyResponse, RequestContext,
    ResponseContext, Route, Router,
};
pub use filters::{
    FilterFactory, HeaderFilter, LoggingFilter, PathRewriteFilter, PathRewriteFilterConfig,
    TimeoutFilter, register_filter,
};
pub use loader::{Foxy, FoxyLoader, LoaderError};
pub use logging::{init_with_config, wrapper};
pub use router::{
    HeaderPredicate, MethodPredicate, PathPredicate, Predicate, PredicateFactory, PredicateRouter,
    QueryPredicate, register_predicate,
};
pub use security::{
    SecurityChain, SecurityProvider, SecurityStage,
    oidc::{OidcConfig, OidcProvider},
    register_security_provider,
};
pub use server::{ProxyServer, ServerConfig};
#[cfg(feature = "swagger-ui")]
pub use server::swagger::{SwaggerSource, SwaggerUIConfig};
