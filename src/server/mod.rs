// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! HTTP server implementation for Foxy.
//!
//! The server is a *thin* wrapper around **hyper-util**.  It owns the
//! listening socket(s) and translates between Hyper's body types and the
//! internal [`ProxyRequest`] / [`ProxyResponse`] generics that the core uses.
//!
//! **Protocol support**  
//! Uses `hyper_util::server::conn::auto::Builder`, so the same
//! connection transparently handles both HTTP/1.1 *and* HTTP/2.
//!
//! ## Body streaming
//! Inbound bodies are **streamed** straight into the upstream connection; no
//! intermediate buffering beyond the configured `server.body_limit` takes
//! place.  This prevents unbounded memory usage when clients upload large
//! files but still gives you a safety-valve.

#[cfg(test)]
mod tests;
mod health;

use std::sync::Arc;
use std::net::SocketAddr;
use std::convert::Infallible;
use tokio::sync::RwLock;
use hyper::body::Incoming;
use hyper::{Request, Response};
use hyper_util::server::conn::auto::Builder as AutoBuilder;
use hyper_util::rt::TokioExecutor;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use bytes::Bytes;
use futures_util::TryStreamExt;
use http_body_util::{BodyExt, Full};
use reqwest::Body;
use serde::{Serialize, Deserialize};
use log::{debug, info, warn, error, trace};
use tokio::signal;
use tokio::task::{Id, JoinSet};
use crate::core::{ProxyCore, ProxyRequest, ProxyResponse, ProxyError, HttpMethod, RequestContext};
use std::collections::HashMap;
use hyper::http::response;
use tokio::sync::oneshot;
use health::HealthServer;

#[cfg(unix)]
use tokio::signal::unix::{signal, SignalKind};

#[cfg(feature = "opentelemetry")]
use opentelemetry::{
    global,
    trace::{TraceContextExt, Tracer},
    KeyValue,
};
use opentelemetry::trace::Span;
#[cfg(feature = "opentelemetry")]
use opentelemetry_http::HeaderExtractor;

/// Configuration for the HTTP server.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    /// Host to bind to
    #[serde(default = "default_host")]
    pub host: String,

    /// Port to listen on
    #[serde(default = "default_port")]
    pub port: u16,

    /// Port to listen on for health/readiness checks
    #[serde(default = "default_health_port")]
    pub health_port: u16,
}

fn default_host() -> String {
    "127.0.0.1".to_string()
}

fn default_port() -> u16 {
    8080
}

fn default_health_port() -> u16 {
    8081
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            host: default_host(),
            port: default_port(),
            health_port: default_health_port(),
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
    /// Shutdown senders for each connection task
    shutdown_senders: Arc<RwLock<HashMap<Id, oneshot::Sender<()>>>>,
}

impl ProxyServer {
    /// Create a new proxy server with the given configuration and proxy core.
    pub fn new(config: ServerConfig, core: Arc<ProxyCore>) -> Self {
        Self { 
            config, 
            core,
            shutdown_senders: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Start the proxy server.
    pub async fn start(&self) -> Result<(), ProxyError> {
        let addr = format!("{}:{}", self.config.host, self.config.port)
            .parse::<SocketAddr>()
            .map_err(|e| ProxyError::Other(format!("Invalid server address: {}", e)))?;
        
        let listener = tokio::net::TcpListener::bind(addr)
            .await
            .map_err(|e| ProxyError::Other(format!("Failed to bind: {}", e)))?;
        
        info!("Foxy proxy listening on http://{}", addr);

        let health_server = HealthServer::new(self.config.health_port);
        health_server.set_ready();

        // prepare signal futures (no errors at creation)
        let ctrl_c = signal::ctrl_c();

        // On Unix, install the SIGTERM stream once and store it in a variable
        #[cfg(unix)]
        let mut term_stream = signal(SignalKind::terminate())
            .map_err(|e| ProxyError::Other(format!("Cannot install SIGTERM handler: {}", e)))?;

        // Build the actual future that we'll await
        #[cfg(unix)]
        let sigterm = term_stream.recv();
        #[cfg(not(unix))]
        let sigterm = std::future::pending();

        // Pin them on the stack so select! can poll them
        tokio::pin!(ctrl_c);
        tokio::pin!(sigterm);

        // Create and use the shared shutdown senders map
        let shutdown_senders = self.shutdown_senders.clone();
        
        // Track spawned connection tasks
        let mut join_set = JoinSet::new();
        let core = self.core.clone();

        // Flag to indicate shutdown has been initiated
        let shutdown_initiated = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let shutdown_initiated_clone = shutdown_initiated.clone();

        loop {
            tokio::select! {
                _ = &mut ctrl_c => {
                    info!("Received Ctrl-C; initiating graceful shutdown");
                    shutdown_initiated_clone.store(true, std::sync::atomic::Ordering::SeqCst);
                    break;
                }
                _ = &mut sigterm => {
                    info!("Received SIGTERM; initiating graceful shutdown");
                    shutdown_initiated_clone.store(true, std::sync::atomic::Ordering::SeqCst);
                    break;
                }
                accept = listener.accept() => {
                    match accept {
                        Ok((stream, remote_addr)) => {
                            // If shutdown has been initiated, reject new connections
                            if shutdown_initiated.load(std::sync::atomic::Ordering::SeqCst) {
                                info!("Rejecting new connection during shutdown");
                                continue;
                            }

                            let core = core.clone();
                            let client_ip = remote_addr.ip().to_string();
                            let (tx, rx) = oneshot::channel();
                            
                            let handle = join_set.spawn(async move {
                                let service = service_fn(move |req: Request<Incoming>| {
                                    debug!("Incoming over {:?}", req.version());
                                    handle_request(req, core.clone(), client_ip.clone())
                                });
                                let io = TokioIo::new(stream);

                                // Use the shutdown signal to properly close connections
                                let builder = {
                                    let mut b = AutoBuilder::new(TokioExecutor::new());
                                    b.http1();
                                    b.http2();
                                    b
                                };

                                // Create a graceful shutdown future
                                let graceful_shutdown = async {
                                    // Wait for the shutdown signal
                                    let _ = rx.await;
                                    debug!("Connection received shutdown signal");
                                };

                                // Create the connection future
                                let connection = builder.serve_connection(io, service);

                                // Run both futures concurrently
                                tokio::select! {
                                    res = connection => {
                                        if let Err(e) = res {
                                            error!("Connection error: {}", e);
                                        }
                                    }
                                    _ = graceful_shutdown => {
                                        debug!("Connection shutting down gracefully");
                                    }
                                }
                            });
                            
                            // Store the shutdown sender for this task
                            shutdown_senders.write().await.insert(handle.id(), tx);
                        }
                        Err(e) => error!("Accept error: {}", e),
                    }
                }
            }
        }

        // Stop accepting connections and signal existing ones to shut down
        info!("Shutting down; waiting for {} connection(s)", join_set.len());
        
        // Signal all connections to close gracefully
        {
            let mut senders = shutdown_senders.write().await;
            for (_, sender) in senders.drain() {
                let _ = sender.send(());
            }
        }
        
        // Wait for connections to complete gracefully with a timeout
        let shutdown_timeout = tokio::time::Duration::from_secs(30);
        let shutdown_future = async {
            while let Some(res) = join_set.join_next().await {
                if let Err(e) = res {
                    error!("Connection task failed: {}", e);
                }
            }
        };

        match tokio::time::timeout(shutdown_timeout, shutdown_future).await {
            Ok(_) => info!("All connections drained gracefully"),
            Err(_) => warn!("Shutdown timed out after {} seconds", shutdown_timeout.as_secs()),
        }
        
        info!("Shutdown complete");
        Ok(())
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

    log::trace!("Converting request: {} {} with {} headers", 
        method, path, headers.len());

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
    log::trace!("Converting response with status {} and {} headers", 
        resp.status, resp.headers.len());
        
    let stream = resp
        .body
        .into_data_stream()
        .map_err(|e| {
            log::error!("Error streaming response body: {}", e);
            std::io::Error::new(std::io::ErrorKind::Other, e)
        });

    let body = Body::wrap_stream(stream);

    let mut builder = Response::builder().status(resp.status);
    match builder.headers_mut() {
        Some(headers) => {
            *headers = resp.headers;
            Ok(())
        },
        None => {
            log::error!("Failed to get mutable headers from response builder");
            Err(ProxyError::Other("unable to set headers".into()))
        }
    }?;

    builder
        .body(body)
        .map_err(|e| {
            let err = ProxyError::Other(e.to_string());
            log::error!("Failed to build response: {}", err);
            err
        })
}

/// Handle an incoming HTTP request.
async fn handle_request(
    req: Request<Incoming>,
    core: Arc<ProxyCore>,
    client_ip: String,
) -> Result<Response<Body>, Infallible> {
    // ---------- OpenTelemetry SERVER span ----------
    #[cfg(feature = "opentelemetry")]
    let mut server_span = {
        let method = req.method().clone();
        let path   = req.uri().path().to_owned();

        let parent_cx = global::get_text_map_propagator(|prop| {
            prop.extract(&HeaderExtractor(req.headers()))
        });

        let mut span = global::tracer("foxy::proxy")
            .start_with_context(format!("HTTP {method} {path}"), &parent_cx);

        span.set_attribute(KeyValue::new("http.method", method.to_string()));
        span.set_attribute(KeyValue::new("http.target", path.clone()));

        span
    };

    /* ---- convert Hyper → ProxyRequest ---- */
    let method = req.method().clone();
    let path = req.uri().path().to_owned();
    
    log::debug!("Received request: {} {}", method, path);
    
    let proxy_req = match convert_hyper_request(req, client_ip.clone()).await {
        Ok(r) => r,
        Err(e) => {
            log::error!("Failed to convert request {} {}: {}", method, path, e);
            return Ok(Response::builder()
                .status(500)
                .body(Body::from("Internal Server Error"))
                .unwrap());
        }
    };

    // ---------- core processing ----------
    let result = core.process_request(proxy_req).await;

    /* ---------- map response ---------- */
    let response: Result<Response<Body>, Infallible> = match result {
        Ok(proxy_resp) => {
            log::debug!(
                "Successfully processed request {} {} -> {}",
                method,
                path,
                proxy_resp.status
            );
            match convert_proxy_response(proxy_resp) {
                Ok(resp) => Ok(resp),
                Err(e) => {
                    log::error!(
                        "Failed to convert response for {} {}: {}",
                        method,
                        path,
                        e
                    );
                    Ok(Response::builder()
                        .status(500)
                        .body(Body::from("Internal Server Error"))
                        .unwrap())
                }
            }
        }
        Err(e) => {
            let (status, msg) = match &e {
                ProxyError::Timeout(d) => {
                    log::warn!("Request {} {} timed out after {:?}", method, path, d);
                    (504, format!("Gateway Timeout after {d:?}"))
                }
                ProxyError::RoutingError(msg) => {
                    log::warn!("Routing error for {} {}: {}", method, path, msg);
                    (404, "Route not found".into())
                }
                ProxyError::SecurityError(msg) => {
                    log::warn!("Security error for {} {}: {}", method, path, msg);
                    (403, "Forbidden".into())
                }
                ProxyError::ClientError(err) => {
                    log::error!("Client error for {} {}: {}", method, path, err);
                    (502, "Bad Gateway".into())
                }
                _ => {
                    log::error!("Internal error processing {} {}: {}", method, path, e);
                    (500, "Internal Server Error".into())
                }
            };

            Ok(Response::builder()
                .status(status)
                .body(Body::from(msg))
                .unwrap())
        }
    };


    // ---------- finalise span ----------
    #[cfg(feature = "opentelemetry")]
    {
        let status_code = response
            .as_ref()
            .map(|r| r.status().as_u16())
            .unwrap_or(500);
        server_span.set_attribute(KeyValue::new(
            "http.status_code",
            status_code as i64,
        ));
        server_span.end();
    }

    response
}