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
//! | `yaml`  | ❌      | Enables YAML configuration alongside TOML/JSON |
//!
//! ## Extension points
//! * `ConfigProvider` – plug in an arbitrary configuration backend
//! * `Filter`         – inject pre/post processing stages
//! * `Predicate`      – custom routing logic
//!
//! See the *examples* directory for a working proxy with logging & path-rewrite.

// Module declarations
pub mod config;
pub mod loader;
pub mod core;
pub mod router;
pub mod filters;
pub mod server;
pub mod security;

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
pub use security::{
    SecurityProvider,
    SecurityStage,
    SecurityChain,
    oidc::{OidcProvider, OidcConfig},
};
pub use server::{ProxyServer, ServerConfig};
