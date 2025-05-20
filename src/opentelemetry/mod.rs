// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! OpenTelemetry bootstrap for Foxy
//!
//! This module centralises **all** tracing/OpenTelemetry initialisation so the
//! rest of the code base only needs a single call.
//!
//! * Feature‑gated behind `opentelemetry` – compiling without the feature
//!   turns every public item into a no‑op.
//! * Reads `endpoint`, `service_name`, **optional custom request headers** and
//!   **static resource attributes** from the proxy configuration block.
//! * Uses the **new 0.29 API** (no `new_exporter`, no `pipeline` helpers).
//! * Builds a **batch** tracing provider and installs `tracing_subscriber`
//!   with `EnvFilter` so runtime `RUST_LOG` works as before.

#![allow(clippy::single_match)]

use std::collections::HashMap;
use std::fmt::Display;
use serde::{Deserialize, Serialize};
use thiserror::Error;
#[cfg(feature = "opentelemetry")]
use {
    opentelemetry_otlp::{WithTonicConfig},
    opentelemetry::{global, KeyValue},
    opentelemetry_sdk::{trace::SdkTracerProvider, Resource},
    opentelemetry_otlp::{SpanExporter, WithExportConfig},
    tonic::metadata::{MetadataMap, MetadataValue},
    opentelemetry_sdk::propagation::TraceContextPropagator
};

/// Errors that can occur during OpenTelemetry operations.
#[derive(Error, Debug)]
pub enum OpenTelemetryError {
    /// Configuration error
    #[error("configuration error: {0}")]
    ConfigError(#[from] crate::config::error::ConfigError),

    /// OpenTelemetry initialization error
    #[error("OpenTelemetry initialization error: {0}")]
    InitError(String),
}

/// Configuration for the OpenTelemetry integration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpenTelemetryConfig {
    /// The endpoint URL for the OpenTelemetry collector.
    #[serde(default = "default_endpoint")]
    pub endpoint: String,

    /// The service name to use for traces.
    #[serde(default = "default_service_name")]
    pub service_name: String,

    /// Whether to include request and response headers in spans.
    #[serde(default = "default_include_headers")]
    pub include_headers: bool,

    /// Whether to include request and response bodies in spans.
    #[serde(default = "default_include_bodies")]
    pub include_bodies: bool,

    /// Maximum body size to include in spans (in bytes).
    #[serde(default = "default_max_body_size")]
    pub max_body_size: usize,

    /// Custom span annotations to add to all spans.
    /// These are key-value pairs that will be added as attributes to all spans.
    #[serde(default)]
    pub span_annotations: HashMap<String, String>,

    /// Custom headers to add to the OpenTelemetry collector requests.
    /// These are key-value pairs that will be added as headers to all collector requests.
    #[serde(default)]
    pub collector_headers: HashMap<String, String>,

    /// Custom resource attributes to add to the OpenTelemetry resource.
    /// These are key-value pairs that will be added as resource attributes to all spans.
    /// Resource attributes are different from span annotations as they are applied at the tracer level
    /// and appear on all spans created by the tracer.
    #[serde(default)]
    pub resource_attributes: HashMap<String, String>,
}

fn default_endpoint() -> String {
    "http://localhost:4317".to_string()
}

fn default_service_name() -> String {
    "foxy-proxy".to_string()
}

fn default_include_headers() -> bool {
    true
}

fn default_include_bodies() -> bool {
    false
}

fn default_max_body_size() -> usize {
    1024
}

impl Default for OpenTelemetryConfig {
    fn default() -> Self {
        Self {
            endpoint: default_endpoint(),
            service_name: default_service_name(),
            include_headers: default_include_headers(),
            include_bodies: default_include_bodies(),
            max_body_size: default_max_body_size(),
            span_annotations: HashMap::new(),
            collector_headers: HashMap::new(),
            resource_attributes: HashMap::new(),
        }
    }
}

impl Display for OpenTelemetryConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "OpenTelemetryConfig {{ endpoint: {}, service_name: {}, include_headers: {}, include_bodies: {}, max_body_size: {}, span_annotations: {:?}, collector_headers: {:?}, resource_attributes: {:?} }}", self.endpoint, self.service_name, self.include_headers, self.include_bodies, self.max_body_size, self.span_annotations, self.collector_headers, self.resource_attributes)
    }
}

/// Initialise tracing + OpenTelemetry. Safe to call once.
#[cfg(feature = "opentelemetry")]
pub fn init(config: Option<OpenTelemetryConfig>) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    if config.is_some() && ! config.as_ref().unwrap().endpoint.is_empty() {
        let config_ref = config.as_ref().unwrap();

        global::set_text_map_propagator(TraceContextPropagator::new());

        // ── exporter ───────────────────────────────────────────────
        let mut exporter_builder = SpanExporter::builder()
            .with_tonic()
            .with_endpoint(config_ref.endpoint.clone());

        if !config_ref.collector_headers.is_empty() {
            let mut meta = MetadataMap::with_capacity(config_ref.collector_headers.len());
            for (k, v) in &config_ref.collector_headers {
                if let (Ok(key), Ok(val)) = (
                    k.parse::<tonic::metadata::MetadataKey<_>>(),
                    MetadataValue::try_from(v.as_str()),
                ) {
                    meta.insert(key, val);
                }
            }
            exporter_builder = exporter_builder.with_metadata(meta);
        }
        let exporter = exporter_builder.build().expect("An error occurred building the OpenTelemetry exporter");

        // ── resource ───────────────────────────────────────────────
        let mut res_builder = Resource::builder().with_service_name(config_ref.service_name.clone());
        if !config_ref.resource_attributes.is_empty() {
            let attrs = config_ref.resource_attributes.iter().map(|(k, v)| KeyValue::new(k.clone(), v.clone()));
            res_builder = res_builder.with_attributes(attrs);
        }
        let resource = res_builder.build();

        // ── tracer provider ────────────────────────────────────────
        let provider = SdkTracerProvider::builder()
            .with_batch_exporter(exporter)
            .with_resource(resource)
            .build();
        global::set_tracer_provider(provider);
    }

    Ok(())
}

/// No‑op version when the feature is disabled.
#[cfg(not(feature = "opentelemetry"))]
pub fn init(_cfg: Option<&serde_json::Value>) -> Result<(), Box<dyn std::error::Error + Send + Sync>> { Ok(()) }

