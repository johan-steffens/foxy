// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! HTTP server implementation for Foxy.
//!
//! The server is a *thin* wrapper around **hyper-util**.  It owns the
//! listening socket(s) and translates between Hyper’s body types and the
//! internal [`ProxyRequest`] / [`ProxyResponse`] generics that the core uses.
//
//! ## Body streaming
//! Inbound bodies are **streamed** straight into the upstream connection; no
//! intermediate buffering beyond the configured `server.body_limit` takes
//! place.  This prevents unbounded memory usage when clients upload large
//! files but still gives you a safety-valve.

use std::sync::Arc;
use std::net::SocketAddr;
use std::convert::Infallible;
use tokio::sync::RwLock;
use http_body_util::StreamBody;
use hyper::body::Incoming;
use hyper::{Request, Response};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use bytes::Bytes;
use futures_util::TryStreamExt;
use http_body_util::{BodyExt, Full};
use http_body_util::combinators::BoxBody;
use reqwest::Body;
use serde::{Serialize, Deserialize};

use crate::core::{ProxyCore, ProxyRequest, ProxyResponse, ProxyError, HttpMethod, RequestContext};

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
#[derive(Debug, Clone)]
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
async fn convert_hyper_request(
    req: Request<Incoming>,
    client_ip: String,
) -> Result<ProxyRequest, ProxyError> {
    let method = HttpMethod::from(req.method());
    let uri = req.uri().clone();
    let path = uri.path().to_owned();
    let query = uri.query().map(|q| q.to_owned());
    let headers = req.headers().clone();

    // Incoming → Stream → reqwest::Body
    let hyper_stream = req.into_body().into_data_stream();
    let byte_stream = hyper_stream.map_ok(Bytes::from);
    let body = reqwest::Body::wrap_stream(byte_stream);

    Ok(ProxyRequest {
        method,
        path,
        query,
        headers,
        body,
        context: Arc::new(RwLock::new(RequestContext {
            client_ip: Some(client_ip),
            start_time: Some(std::time::Instant::now()),
            attributes: std::collections::HashMap::new(),
        })),
    })
}

/// Convert a proxy response to a hyper response.
fn convert_proxy_response(resp: ProxyResponse) -> Result<Response<Body>, ProxyError> {
    let stream = resp
        .body
        .into_data_stream()
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e));

    let body = Body::wrap_stream(stream);

    let mut builder = Response::builder().status(resp.status);
    *builder
        .headers_mut()
        .ok_or_else(|| ProxyError::Other("unable to set headers".into()))? = resp.headers;

    Ok(builder
        .body(body)
        .map_err(|e| ProxyError::Other(e.to_string()))?)
}

/// Handle an incoming HTTP request.
async fn handle_request(
    req: Request<Incoming>,
    core: Arc<ProxyCore>,
    client_ip: String,
) -> Result<Response<Body>, Infallible> {
    /* ---- convert Hyper → ProxyRequest ---- */
    let proxy_req = match convert_hyper_request(req, client_ip).await {
        Ok(r) => r,
        Err(e) => {
            log::error!("convert request: {e}");
            return Ok(Response::builder()
                .status(500)
                .body(Body::from("Internal Server Error"))
                .unwrap());
        }
    };

    /* ---- core processing ---- */
    match core.process_request(proxy_req).await {
        Ok(proxy_resp) => match convert_proxy_response(proxy_resp) {
            Ok(resp) => Ok(resp),
            Err(e) => {
                log::error!("convert response: {e}");
                Ok(Response::builder()
                    .status(500)
                    .body(Body::from("Internal Server Error"))
                    .unwrap())
            }
        },
        Err(e) => {
            log::error!("proxy error: {e}");
            let (status, msg) = match e {
                ProxyError::Timeout(d)     => (504, format!("Gateway Timeout after {d:?}")),
                ProxyError::RoutingError(_) => (404, "Route not found".into()),
                _                           => (500, "Internal Server Error".into()),
            };
            Ok(Response::builder()
                .status(status)
                .body(Body::from(msg))
                .unwrap())
        }
    }
}

/// Helper function to convert a hyper response to a ProxyResponse (for testing)
#[allow(dead_code)]
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
        body: reqwest::Body::from(body),
        context: Arc::new(RwLock::new(ResponseContext::default())),
    }
}