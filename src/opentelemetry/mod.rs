// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! OpenTelemetry integration for Foxy
//!
//! This module provides OpenTelemetry tracing support for Foxy, allowing
//! users to configure an OpenTelemetry collector endpoint that will create
//! traces for all calls going through the proxy.
//!
//! The module is only included when the "opentelemetry" feature is enabled.

#[cfg(test)]
mod tests;

use std::sync::Arc;
use std::time::Instant;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use async_trait::async_trait;
use tracing::{info, debug, error, Span, instrument};
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::Layer;
use opentelemetry::sdk::Resource;
use opentelemetry::KeyValue;
use opentelemetry::runtime::Tokio;
use opentelemetry_semantic_conventions::resource::SERVICE_NAME;

use crate::core::{Filter, FilterType, ProxyRequest, ProxyResponse, ProxyError, ProxyCore};

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
    pub span_annotations: std::collections::HashMap<String, String>,
    
    /// Custom headers to add to the OpenTelemetry collector requests.
    /// These are key-value pairs that will be added as headers to all collector requests.
    #[serde(default)]
    pub collector_headers: std::collections::HashMap<String, String>,
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
            span_annotations: std::collections::HashMap::new(),
            collector_headers: std::collections::HashMap::new(),
        }
    }
}

/// Initialize OpenTelemetry with the given configuration.
pub fn init_opentelemetry(config: &OpenTelemetryConfig) -> Result<(), OpenTelemetryError> {
    use opentelemetry::sdk::trace::Config;
    use opentelemetry_otlp::WithExportConfig;
    
    // Set up a global resource with the service name
    let resource = Resource::new(vec![
        KeyValue::new(SERVICE_NAME, config.service_name.clone()),
    ]);
    
    // Configure the OpenTelemetry exporter with explicit resource
    let mut exporter = opentelemetry_otlp::new_exporter()
        .tonic()
        .with_endpoint(&config.endpoint);
    
    // Add custom headers to the collector if configured
    if !config.collector_headers.is_empty() {
        let mut headers = tonic::metadata::MetadataMap::new();
        for (key, value) in &config.collector_headers {
            if let Ok(key_str) = tonic::metadata::MetadataKey::from_bytes(key.as_bytes()) {
                headers.insert(key_str, value.parse().unwrap_or_default());
            }
        }
        exporter = exporter.with_metadata(headers);
    }
    
    let tracer = opentelemetry_otlp::new_pipeline()
        .tracing()
        .with_exporter(exporter)
        .with_trace_config(
            Config::default()
                .with_resource(resource)
                .with_sampler(opentelemetry::sdk::trace::Sampler::AlwaysOn)
        )
        .install_batch(Tokio)
        .map_err(|e| OpenTelemetryError::InitError(e.to_string()))?;

    // Create a tracing layer with the configured tracer
    let telemetry = tracing_opentelemetry::layer()
        .with_tracer(tracer);

    // Create a subscriber with the OpenTelemetry layer
    let subscriber = tracing_subscriber::registry()
        .with(telemetry)
        .with(tracing_subscriber::fmt::layer()
            .with_filter(tracing_subscriber::filter::LevelFilter::INFO));

    // Set the subscriber as the global default
    match tracing::subscriber::set_global_default(subscriber) {
        Ok(_) => {
            log::info!("OpenTelemetry initialized with collector endpoint: {} and service name: {}", 
                      config.endpoint, config.service_name);
        },
        Err(e) => {
            log::warn!("Could not set OpenTelemetry as global subscriber (this is normal if logging was already initialized): {}", e);
            log::info!("OpenTelemetry initialized with collector endpoint: {}", config.endpoint);
        }
    }
    
    Ok(())
}

/// A filter that creates OpenTelemetry spans for requests and responses.
#[derive(Debug)]
pub struct OpenTelemetryFilter {
    config: OpenTelemetryConfig,
}

impl OpenTelemetryFilter {
    /// Create a new OpenTelemetry filter with the given configuration.
    pub fn new(config: OpenTelemetryConfig) -> Self {
        Self { config }
    }
}

#[async_trait]
impl Filter for OpenTelemetryFilter {
    fn filter_type(&self) -> FilterType {
        FilterType::Both
    }

    fn name(&self) -> &str {
        "opentelemetry"
    }

    #[instrument(name = "http.request", skip(self, request), fields(
        service.name = %self.config.service_name,
        http.method = request.method.to_string(),
        http.url = request.path,
        http.target = tracing::field::Empty,
        http.flavor = "1.1",
        http.user_agent = tracing::field::Empty,
        http.status_code = tracing::field::Empty,
        otel.kind = "server",
        otel.status_code = tracing::field::Empty
    ))]
    async fn pre_filter(&self, request: ProxyRequest) -> Result<ProxyRequest, ProxyError> {
        // Extract request information
        let method = request.method.to_string();
        let path = request.path.clone();
        let service_name = self.config.service_name.clone();
        
        // Record span attributes
        let span = Span::current();
        span.record("http.method", &tracing::field::display(&method));
        span.record("http.url", &tracing::field::display(&path));
        span.record("http.target", &tracing::field::display(&path));
        
        // Add custom span annotations if configured
        for (key, value) in &self.config.span_annotations {
            span.record(key, &tracing::field::display(value));
        }
        
        // Store the start time in the request context
        let start_time = Instant::now();
        {
            let mut ctx = request.context.write().await;
            ctx.attributes.insert(
                "otel_start_time".to_string(),
                serde_json::Value::Number(serde_json::Number::from(start_time.elapsed().as_millis() as u64))
            );
            
            // Also store the service name
            ctx.attributes.insert(
                "otel_service_name".to_string(),
                serde_json::Value::String(service_name.clone())
            );
            
            // Store the span context for propagation
            ctx.attributes.insert(
                "otel_span_id".to_string(),
                serde_json::Value::String(format!("{:?}", span.id()))
            );
        }
        
        // Log headers if configured
        if self.config.include_headers {
            for (name, value) in request.headers.iter() {
                if let Ok(value_str) = value.to_str() {
                    if name == "user-agent" {
                        span.record("http.user_agent", &tracing::field::display(value_str));
                    }
                    debug!("Request header: {} = {}", name, value_str);
                }
            }
        }
        
        info!(
            "Starting request {} {} for service {}",
            method,
            path,
            service_name
        );
        
        Ok(request)
    }

    #[instrument(name = "http.response", skip(self, request, response))]
    async fn post_filter(
        &self,
        request: ProxyRequest,
        response: ProxyResponse,
    ) -> Result<ProxyResponse, ProxyError> {
        // Record response information in the current span
        let span = Span::current();
        span.record("http.status_code", &tracing::field::display(response.status));
        
        // Set the status based on the HTTP status code
        if response.status >= 400 {
            span.record("otel.status_code", &tracing::field::display("ERROR"));
        } else {
            span.record("otel.status_code", &tracing::field::display("OK"));
        }
        
        // Add custom span annotations if configured
        for (key, value) in &self.config.span_annotations {
            span.record(key, &tracing::field::display(value));
        }
        
        // Get the start time and service name from the request context
        let mut duration_ms = 0;
        let mut service_name = self.config.service_name.clone();
        {
            let ctx = request.context.read().await;
            if let Some(start_time_value) = ctx.attributes.get("otel_start_time") {
                if let Some(start_ms) = start_time_value.as_u64() {
                    duration_ms = Instant::now().elapsed().as_millis() as u64 - start_ms;
                }
            }
            
            if let Some(svc_name) = ctx.attributes.get("otel_service_name") {
                if let Some(name) = svc_name.as_str() {
                    service_name = name.to_string();
                }
            }
        }
        
        // Log headers if configured
        if self.config.include_headers {
            for (name, value) in response.headers.iter() {
                if let Ok(value_str) = value.to_str() {
                    debug!("Response header: {} = {}", name, value_str);
                }
            }
        }
        
        info!(
            "Completed request with status {} in {}ms for service {}",
            response.status,
            duration_ms,
            service_name
        );
        
        Ok(response)
    }
}

/// Factory for creating OpenTelemetry filters from configuration.
pub struct OpenTelemetryFilterFactory;

impl OpenTelemetryFilterFactory {
    /// Create a new OpenTelemetry filter from the given configuration.
    pub fn create(config: serde_json::Value) -> Result<Arc<dyn Filter>, ProxyError> {
        let config: OpenTelemetryConfig = serde_json::from_value(config)
            .map_err(|e| ProxyError::FilterError(format!("Invalid OpenTelemetry configuration: {}", e)))?;
        
        Ok(Arc::new(OpenTelemetryFilter::new(config)))
    }
}

/// Register the OpenTelemetry filter with the proxy core.
pub async fn register_filter(proxy_core: &ProxyCore, config: &OpenTelemetryConfig) -> Result<(), ProxyError> {
    let filter = Arc::new(OpenTelemetryFilter::new(config.clone()));
    proxy_core.add_global_filter(filter).await;
    Ok(())
}
