// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use super::*;
use crate::core::{HttpMethod, ProxyRequest, RequestContext};
use crate::ProxyError;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use reqwest::header::HeaderMap;

#[tokio::test]
async fn test_opentelemetry_config_defaults() {
    let config = OpenTelemetryConfig::default();
    
    assert_eq!(config.endpoint, "http://localhost:4317");
    assert_eq!(config.service_name, "foxy-proxy");
    assert_eq!(config.include_headers, true);
    assert_eq!(config.include_bodies, false);
    assert_eq!(config.max_body_size, 1024);
}

#[tokio::test]
async fn test_opentelemetry_filter_name_and_type() {
    let config = OpenTelemetryConfig::default();
    let filter = OpenTelemetryFilter::new(config);
    
    assert_eq!(filter.name(), "opentelemetry");
    assert_eq!(filter.filter_type(), FilterType::Both);
}

#[tokio::test]
async fn test_opentelemetry_filter_pre_filter() {
    let config = OpenTelemetryConfig::default();
    let filter = OpenTelemetryFilter::new(config);
    
    let mut headers = HeaderMap::new();
    headers.insert("content-type", "application/json".parse().unwrap());
    
    let context = RequestContext {
        client_ip: Some("127.0.0.1".to_string()),
        start_time: Some(std::time::Instant::now()),
        attributes: {
            let mut map = HashMap::new();
            map.insert("route_id".to_string(), serde_json::Value::String("test-route".to_string()));
            map.insert("target".to_string(), serde_json::Value::String("https://example.com".to_string()));
            map
        },
    };
    
    let req = ProxyRequest {
        method: HttpMethod::Get,
        path: "/test/path".to_string(),
        query: None,
        headers,
        body: reqwest::Body::from(""),
        context: Arc::new(RwLock::new(context)),
    };
    
    let result = filter.pre_filter(req).await;
    assert!(result.is_ok());
    
    let req = result.unwrap();
    let ctx = req.context.read().await;
    assert!(ctx.attributes.contains_key("otel_start_time"));
}
