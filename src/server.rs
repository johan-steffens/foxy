// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! HTTP server implementation for Foxy.
//!
//! This module provides the HTTP server that listens for incoming requests
//! and forwards them to the proxy core.

use std::sync::Arc;
use std::net::SocketAddr;
use std::convert::Infallible;
use tokio::sync::RwLock;
use hyper::body::Incoming;
use hyper::{Request, Response};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use reqwest::Body;
use serde::{Serialize, Deserialize};

use crate::config::Config;
use crate::core::{ProxyCore, ProxyRequest, ProxyResponse, ProxyError, HttpMethod, RequestContext, ResponseContext};
use crate::router::PathRouter;

/// Configuration for the HTTP server.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    /// Host to bind to
    #[serde(default = "default_host")]
    pub host: String,

    /// Port to listen on
    #[serde(default = "default_port")]
    pub port: u16,
}

fn default_host() -> String {
    "127.0.0.1".to_string()
}

fn default_port() -> u16 {
    8080
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            host: default_host(),
            port: default_port(),
        }
    }
}

/// HTTP server for the proxy.
#[derive(Debug)]
pub struct ProxyServer {
    /// Server configuration
    config: ServerConfig,
    /// Proxy core
    core: Arc<ProxyCore>,
}

impl ProxyServer {
    /// Create a new proxy server with the given configuration and proxy core.
    pub fn new(config: ServerConfig, core: Arc<ProxyCore>) -> Self {
        Self { config, core }
    }

    /// Start the proxy server.
    pub async fn start(&self) -> Result<(), ProxyError> {
        let addr: SocketAddr = format!("{}:{}", self.config.host, self.config.port)
            .parse()
            .map_err(|e| ProxyError::Other(format!("Invalid server address: {}", e)))?;

        let core = self.core.clone();

        // Create a TCP listener
        let listener = tokio::net::TcpListener::bind(addr).await
            .map_err(|e| ProxyError::Other(format!("Failed to bind to address: {}", e)))?;
        
        log::info!("Foxy proxy server listening on http://{}", addr);
        
        // Accept connections
        loop {
            let (stream, remote_addr) = match listener.accept().await {
                Ok(conn) => conn,
                Err(e) => {
                    log::error!("Failed to accept connection: {}", e);
                    continue;
                }
            };
            
            let core = core.clone();
            let client_ip = remote_addr.ip().to_string();
            
            // Spawn a task to handle the connection
            tokio::spawn(async move {
                let service = service_fn(move |req| {
                    let core = core.clone();
                    let client_ip = client_ip.clone();
                    handle_request(req, core, client_ip)
                });
                
                // Wrap the TcpStream with TokioIo for compatibility with hyper
                let io = TokioIo::new(stream);
                
                if let Err(e) = http1::Builder::new()
                    .serve_connection(io, service)
                    .await {
                    log::error!("Error serving connection: {}", e);
                }
            });
        }
    }
}

/// Convert a hyper request to a proxy request.
async fn convert_hyper_request(req: Request<Incoming>, client_ip: String) -> Result<ProxyRequest, ProxyError> {
    // Extract components from the hyper request
    let method = HttpMethod::from(req.method());
    let uri = req.uri();
    let path = uri.path().to_string();
    let query = uri.query().map(|q| q.to_string());
    let headers = req.headers().clone();

    // Read the body
    let body_bytes = req.into_body().collect()
        .await
        .map_err(|e| ProxyError::Other(format!("Failed to read request body: {}", e)))?
        .to_bytes()
        .to_vec();

    // Create the request context with client IP
    let context = Arc::new(RwLock::new(RequestContext {
        client_ip: Some(client_ip),
        start_time: Some(std::time::Instant::now()),
        attributes: std::collections::HashMap::new(),
    }));

    Ok(ProxyRequest {
        method,
        path,
        query,
        headers,
        body: body_bytes,
        context,
    })
}

/// Convert a proxy response to a hyper response.
fn convert_proxy_response(resp: ProxyResponse) -> Result<Response<Full<Bytes>>, ProxyError> {
    // Create a new hyper response
    let mut builder = Response::builder()
        .status(resp.status);

    // Add headers
    let headers = builder.headers_mut().ok_or_else(||
        ProxyError::Other("Failed to get response headers".to_string())
    )?;

    for (name, value) in resp.headers.iter() {
        headers.insert(name, value.clone());
    }

    // Create the response with the body
    let response = builder
        .body(Full::new(Bytes::from(resp.body)))
        .map_err(|e| ProxyError::Other(format!("Failed to create response: {}", e)))?;

    Ok(response)
}

/// Handle an incoming HTTP request.
async fn handle_request(
    req: Request<Incoming>,
    core: Arc<ProxyCore>,
    client_ip: String,
) -> Result<Response<Full<Bytes>>, Infallible> {
    // Convert the hyper request to a proxy request
    let proxy_req = match convert_hyper_request(req, client_ip).await {
        Ok(req) => req,
        Err(e) => {
            log::error!("Failed to convert request: {}", e);
            return Ok(Response::builder()
                .status(500)
                .body(Full::new(Bytes::from("Internal Server Error")))
                .unwrap());
        }
    };

    // Process the request through the proxy core
    match core.process_request(proxy_req).await {
        Ok(proxy_resp) => {
            // Convert the proxy response back to a hyper response
            match convert_proxy_response(proxy_resp) {
                Ok(resp) => Ok(resp),
                Err(e) => {
                    log::error!("Failed to convert response: {}", e);
                    Ok(Response::builder()
                        .status(500)
                        .body(Full::new(Bytes::from("Internal Server Error")))
                        .unwrap())
                }
            }
        },
        Err(e) => {
            log::error!("Proxy error: {}", e);

            // Create an appropriate error response
            let (status, message) = match e {
                ProxyError::Timeout(duration) =>
                    (504, format!("Gateway Timeout: Request timed out after {:?}", duration)),
                ProxyError::RoutingError(_) =>
                    (404, "Not Found: No route matched the request".to_string()),
                _ =>
                    (500, "Internal Server Error".to_string()),
            };

            Ok(Response::builder()
                .status(status)
                .body(Full::new(Bytes::from(message)))
                .unwrap())
        }
    }
}

/// Helper function to convert a hyper response to a ProxyResponse (for testing)
fn convert_hyper_response(resp: Response<Full<Bytes>>) -> ProxyResponse {
    use crate::core::ResponseContext;

    let status = resp.status().as_u16();
    let headers = resp.headers().clone();

    // In a real implementation, you would read the body asynchronously,
    // but for testing purposes we'll use an empty body
    let body = Vec::new();

    ProxyResponse {
        status,
        headers,
        body,
        context: Arc::new(RwLock::new(ResponseContext::default())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyper::{StatusCode, Method};
    use reqwest::Body;
    use reqwest::header::HeaderValue;

    #[tokio::test]
    async fn test_convert_request() {
        // Create a test hyper request
        let hyper_req = Request::builder()
            .method(Method::GET)
            .uri("http://example.com/test?query=value")
            .header("content-type", "application/json")
            .body(Body::from(r#"{"test": "value"}"#))
            .unwrap();

        // Convert to a proxy request
        let client_ip = "127.0.0.1".to_string();
        let proxy_req = convert_hyper_request(hyper_req, client_ip.clone()).await.unwrap();

        // Verify conversion
        assert_eq!(proxy_req.method, HttpMethod::Get);
        assert_eq!(proxy_req.path, "/test");
        assert_eq!(proxy_req.query, Some("query=value".to_string()));
        assert_eq!(
            proxy_req.headers.get("content-type").unwrap(),
            "application/json"
        );
        assert_eq!(
            String::from_utf8(proxy_req.body.clone()).unwrap(),
            r#"{"test": "value"}"#
        );

        // Verify context
        let context = proxy_req.context.read().await;
        assert_eq!(context.client_ip, Some(client_ip));
        assert!(context.start_time.is_some());
    }

    #[test]
    fn test_convert_response() {
        use crate::core::ResponseContext;

        // Create a test proxy response
        let mut headers = hyper::header::HeaderMap::new();
        headers.insert("content-type", HeaderValue::from_static("application/json"));

        let proxy_resp = ProxyResponse {
            status: 200,
            headers,
            body: r#"{"result": "success"}"#.as_bytes().to_vec(),
            context: Arc::new(RwLock::new(ResponseContext::default())),
        };

        // Convert to a hyper response
        let hyper_resp = convert_proxy_response(proxy_resp).unwrap();

        // Verify conversion
        assert_eq!(hyper_resp.status(), StatusCode::OK);
        assert_eq!(
            hyper_resp.headers().get("content-type").unwrap(),
            "application/json"
        );
    }
}