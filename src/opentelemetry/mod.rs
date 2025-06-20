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
    opentelemetry_sdk::propagation::TraceContextPropagator,
    opentelemetry_semantic_conventions::attribute::{
        SERVICE_VERSION, SERVICE_INSTANCE_ID, DEPLOYMENT_ENVIRONMENT
    }
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
        let svc_version   = env!("CARGO_PKG_VERSION");
        let deploy_env    = std::env::var("FOXY_DEPLOY_ENV").unwrap_or_else(|_| "local".into());
        let instance_id   = hostname::get()
            .ok()
            .and_then(|h| h.into_string().ok())
            .unwrap_or_else(|| "unknown-host".into());
        
        let mut res_builder = Resource::builder().with_service_name(config_ref.service_name.clone())
            .with_attribute(KeyValue::new(SERVICE_VERSION, svc_version))
            .with_attribute(KeyValue::new(DEPLOYMENT_ENVIRONMENT, deploy_env))
            .with_attribute(KeyValue::new(SERVICE_INSTANCE_ID, instance_id));
        
        
        if !config_ref.resource_attributes.is_empty() {
            let attrs = config_ref.resource_attributes.iter().map(|(k, v)| KeyValue::new(k.clone(), v.clone()));
            res_builder = res_builder.with_attributes(attrs);
        };
        
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
pub fn init(_cfg: Option<OpenTelemetryConfig>) -> Result<(), Box<dyn std::error::Error + Send + Sync>> { Ok(()) }

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn test_opentelemetry_config_default() {
        let config = OpenTelemetryConfig::default();

        assert_eq!(config.endpoint, "http://localhost:4317");
        assert_eq!(config.service_name, "foxy-proxy");
        assert!(config.include_headers);
        assert!(!config.include_bodies);
        assert_eq!(config.max_body_size, 1024);
        assert!(config.span_annotations.is_empty());
        assert!(config.collector_headers.is_empty());
        assert!(config.resource_attributes.is_empty());
    }

    #[test]
    fn test_opentelemetry_config_custom() {
        let mut span_annotations = HashMap::new();
        span_annotations.insert("custom.key".to_string(), "custom.value".to_string());

        let mut collector_headers = HashMap::new();
        collector_headers.insert("X-API-Key".to_string(), "secret-key".to_string());

        let mut resource_attributes = HashMap::new();
        resource_attributes.insert("service.version".to_string(), "1.0.0".to_string());

        let config = OpenTelemetryConfig {
            endpoint: "http://custom-collector:4317".to_string(),
            service_name: "custom-service".to_string(),
            include_headers: false,
            include_bodies: true,
            max_body_size: 2048,
            span_annotations,
            collector_headers,
            resource_attributes,
        };

        assert_eq!(config.endpoint, "http://custom-collector:4317");
        assert_eq!(config.service_name, "custom-service");
        assert!(!config.include_headers);
        assert!(config.include_bodies);
        assert_eq!(config.max_body_size, 2048);
        assert_eq!(config.span_annotations.get("custom.key"), Some(&"custom.value".to_string()));
        assert_eq!(config.collector_headers.get("X-API-Key"), Some(&"secret-key".to_string()));
        assert_eq!(config.resource_attributes.get("service.version"), Some(&"1.0.0".to_string()));
    }

    #[test]
    fn test_opentelemetry_config_display() {
        let config = OpenTelemetryConfig::default();
        let display_str = format!("{}", config);

        assert!(display_str.contains("endpoint: http://localhost:4317"));
        assert!(display_str.contains("service_name: foxy-proxy"));
        assert!(display_str.contains("include_headers: true"));
        assert!(display_str.contains("include_bodies: false"));
        assert!(display_str.contains("max_body_size: 1024"));
    }

    #[test]
    fn test_opentelemetry_config_serialization() {
        let config = OpenTelemetryConfig::default();

        // Test serialization
        let serialized = serde_json::to_string(&config).expect("Failed to serialize config");
        assert!(serialized.contains("\"endpoint\":\"http://localhost:4317\""));
        assert!(serialized.contains("\"service_name\":\"foxy-proxy\""));

        // Test deserialization
        let deserialized: OpenTelemetryConfig = serde_json::from_str(&serialized)
            .expect("Failed to deserialize config");
        assert_eq!(deserialized.endpoint, config.endpoint);
        assert_eq!(deserialized.service_name, config.service_name);
        assert_eq!(deserialized.include_headers, config.include_headers);
        assert_eq!(deserialized.include_bodies, config.include_bodies);
        assert_eq!(deserialized.max_body_size, config.max_body_size);
    }

    #[test]
    fn test_opentelemetry_config_partial_deserialization() {
        // Test that partial JSON can be deserialized with defaults
        let partial_json = r#"{"endpoint": "http://custom:4317"}"#;
        let config: OpenTelemetryConfig = serde_json::from_str(partial_json)
            .expect("Failed to deserialize partial config");

        assert_eq!(config.endpoint, "http://custom:4317");
        assert_eq!(config.service_name, "foxy-proxy"); // default
        assert!(config.include_headers); // default
        assert!(!config.include_bodies); // default
        assert_eq!(config.max_body_size, 1024); // default
    }

    #[test]
    fn test_opentelemetry_error_display() {
        let config_error = crate::config::error::ConfigError::ParseError("test error".to_string());
        let otel_error = OpenTelemetryError::ConfigError(config_error);

        let error_str = format!("{}", otel_error);
        assert!(error_str.contains("configuration error"));
        assert!(error_str.contains("test error"));
    }

    #[test]
    fn test_opentelemetry_init_error() {
        let init_error = OpenTelemetryError::InitError("initialization failed".to_string());

        let error_str = format!("{}", init_error);
        assert!(error_str.contains("OpenTelemetry initialization error"));
        assert!(error_str.contains("initialization failed"));
    }

    #[test]
    fn test_default_functions() {
        assert_eq!(default_endpoint(), "http://localhost:4317");
        assert_eq!(default_service_name(), "foxy-proxy");
        assert!(default_include_headers());
        assert!(!default_include_bodies());
        assert_eq!(default_max_body_size(), 1024);
    }

    // Test the no-op version when feature is disabled
    #[cfg(not(feature = "opentelemetry"))]
    #[test]
    fn test_init_noop() {
        let config = OpenTelemetryConfig::default();
        let result = init(Some(config));
        assert!(result.is_ok());
    }

    // Test the actual init function when feature is enabled
    #[cfg(feature = "opentelemetry")]
    #[test]
    fn test_init_with_empty_endpoint() {
        let mut config = OpenTelemetryConfig::default();
        config.endpoint = "".to_string();

        let result = init(Some(config));
        assert!(result.is_ok());
    }

    #[cfg(feature = "opentelemetry")]
    #[test]
    fn test_init_with_none_config() {
        let result = init(None);
        assert!(result.is_ok());
    }

    #[cfg(feature = "opentelemetry")]
    #[test]
    fn test_init_with_custom_headers() {
        let mut config = OpenTelemetryConfig::default();
        config.endpoint = "http://localhost:4317".to_string();
        config.collector_headers.insert("x-api-key".to_string(), "test-key".to_string());
        config.collector_headers.insert("authorization".to_string(), "Bearer token".to_string());

        let result = init(Some(config));
        assert!(result.is_ok());
    }

    #[cfg(feature = "opentelemetry")]
    #[test]
    fn test_init_with_custom_resource_attributes() {
        let mut config = OpenTelemetryConfig::default();
        config.endpoint = "http://localhost:4317".to_string();
        config.resource_attributes.insert("service.version".to_string(), "1.0.0".to_string());
        config.resource_attributes.insert("deployment.environment".to_string(), "test".to_string());

        let result = init(Some(config));
        assert!(result.is_ok());
    }

    #[cfg(feature = "opentelemetry")]
    #[test]
    fn test_init_with_invalid_headers() {
        let mut config = OpenTelemetryConfig::default();
        config.endpoint = "http://localhost:4317".to_string();
        // Add headers with invalid characters that should be filtered out
        config.collector_headers.insert("invalid\nheader".to_string(), "value".to_string());
        config.collector_headers.insert("valid-header".to_string(), "valid-value".to_string());

        let result = init(Some(config));
        assert!(result.is_ok());
    }
}

