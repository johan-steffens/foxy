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

use std::borrow::Cow;
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
    Context,
    trace::{Span, SpanBuilder, SpanKind, Status, SpanRef}
};
#[cfg(feature = "opentelemetry")]
use opentelemetry_http::HeaderExtractor;
#[cfg(feature = "opentelemetry")]
use opentelemetry_semantic_conventions::attribute::{HTTP_FLAVOR, HTTP_HOST, HTTP_METHOD, HTTP_REQUEST_CONTENT_LENGTH, HTTP_RESPONSE_STATUS_CODE, HTTP_SCHEME, HTTP_STATUS_CODE, HTTP_URL, HTTP_USER_AGENT, NET_PEER_IP};

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
                            let shutdown_senders_clone = shutdown_senders.clone();
                            
                            let handle = join_set.spawn(async move {
                                let task_id = tokio::task::id();
                                
                                let service = service_fn(move |req: Request<Incoming>| {
                                    debug!("Incoming over {:?}", &req.version());
                                    handle_request(req, core.clone(), client_ip.clone())
                                });
                                let io = TokioIo::new(stream);
        
                                let builder = {
                                    let mut b = AutoBuilder::new(TokioExecutor::new());
                                    b.http1();
                                    b.http2();
                                    b
                                };
        
                                // Create the connection
                                let connection = builder.serve_connection(io, service);
                                
                                // Pin the connection and enable graceful shutdown
                                let mut conn = std::pin::pin!(connection);
        
                                // Run the connection with graceful shutdown
                                tokio::select! {
                                    res = &mut conn => {
                                        match res {
                                            Ok(()) => debug!("Connection closed normally"),
                                            Err(e) => {
                                                // Check if it's a graceful close by examining the error message
                                                let err_str = e.to_string();
                                                if !err_str.contains("connection closed") && 
                                                   !err_str.contains("connection reset") {
                                                    error!("Connection error: {}", e);
                                                }
                                            }
                                        }
                                    }
                                    _ = rx => {
                                        debug!("Connection received shutdown signal, waiting for graceful close");
                                        conn.as_mut().graceful_shutdown();
                                        
                                        // Continue running the connection until it completes
                                        match conn.await {
                                            Ok(()) => debug!("Connection closed gracefully after shutdown signal"),
                                            Err(e) => {
                                                let err_str = e.to_string();
                                                if !err_str.contains("connection closed") && 
                                                   !err_str.contains("connection reset") {
                                                    error!("Connection error during graceful shutdown: {}", e);
                                                }
                                            }
                                        }
                                    }
                                }
                                
                                // Clean up the shutdown sender for this task
                                shutdown_senders_clone.write().await.remove(&task_id);
                                debug!("Connection task {:?} completed", task_id);
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
            info!("Signaling {} connections to shut down", senders.len());
            for (task_id, sender) in senders.drain() {
                debug!("Sending shutdown signal to task {:?}", task_id);
                let _ = sender.send(());
            }
        }

        // Wait for connections to complete gracefully with a timeout
        let shutdown_timeout = tokio::time::Duration::from_secs(30);
        let start_time = tokio::time::Instant::now();

        let shutdown_future = async {
            let mut completed = 0;
            let total = join_set.len();

            while let Some(res) = join_set.join_next().await {
                completed += 1;
                match res {
                    Ok(_) => debug!("Connection task completed ({}/{})", completed, total),
                    Err(e) if e.is_cancelled() => debug!("Connection task cancelled ({}/{})", completed, total),
                    Err(e) => error!("Connection task failed ({}/{}): {}", completed, total, e),
                }

                let elapsed = start_time.elapsed();
                if completed % 10 == 0 || total - completed < 10 {
                    info!("Shutdown progress: {}/{} connections closed (elapsed: {:.1}s)", 
                  completed, total, elapsed.as_secs_f32());
                }
            }
        };

        match tokio::time::timeout(shutdown_timeout, shutdown_future).await {
            Ok(_) => {
                let elapsed = start_time.elapsed();
                info!("All connections drained gracefully in {:.1}s", elapsed.as_secs_f32());
            }
            Err(_) => {
                warn!("Shutdown timed out after {} seconds, some connections may be forcefully closed", 
              shutdown_timeout.as_secs());
                // Cancel remaining tasks
                join_set.shutdown().await;
            }
        }

        // Ensure health server is also shut down
        drop(health_server);

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
    let mut_headers = builder.headers_mut().ok_or_else(|| {
        log::error!("Failed to get mutable headers from response builder");
        ProxyError::Other("Failed to build response: unable to get mutable headers".into())
    })?;
    *mut_headers = resp.headers;

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
    let span_context = {
        let method = req.method().as_str().to_owned();
        let path   = req.uri().path().to_owned();
        let full_url = req.uri().clone().to_string();
        let scheme = req.uri().scheme_str().unwrap_or("http").to_owned();
        let host = req.headers().get("host").and_then(|v| v.to_str().ok()).unwrap_or("-").to_owned();
        let http_version = match req.version() { hyper::Version::HTTP_10 => "1.0", hyper::Version::HTTP_11 => "1.1", hyper::Version::HTTP_2 => "2", hyper::Version::HTTP_3 => "3", _ => "unknown" };
        let req_content_len = req.headers().get("content-length").and_then(|v| v.to_str().ok()).and_then(|s| s.parse::<i64>().ok()).unwrap_or(0);
        let user_agent = req.headers().get("user-agent").and_then(|v| v.to_str().ok()).unwrap_or("-").to_owned();
        let peer_ip = client_ip.as_str().to_owned();

        let context = extract_context_from_request(&req);
        let mut span = global::tracer("foxy::proxy")
            .build_with_context(SpanBuilder {
                name: Cow::from(format!("{method} {path}")),
                span_kind: Some(SpanKind::Server),
                ..Default::default()
            }, &context);

        span.set_attributes([
            KeyValue::new(HTTP_METHOD, method),
            KeyValue::new(HTTP_URL, full_url.clone()),
            KeyValue::new(HTTP_SCHEME, scheme),
            KeyValue::new(HTTP_HOST, host),
            KeyValue::new(HTTP_FLAVOR, http_version),
            KeyValue::new(HTTP_REQUEST_CONTENT_LENGTH, req_content_len),
            KeyValue::new(HTTP_USER_AGENT, user_agent),
            KeyValue::new(NET_PEER_IP, peer_ip),
        ]);

        context.with_span(span)
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
    #[cfg(feature = "opentelemetry")]
    let span_clone = span_context.clone();

    #[cfg(feature = "opentelemetry")]
    let span_ref = span_context.span();

    #[cfg(feature = "opentelemetry")]
    let result = core.process_request(proxy_req, Some(span_clone)).await;

    #[cfg(not(feature = "opentelemetry"))]
    let result = core.process_request(proxy_req).await;

    // ---------- finalise span ----------
    #[cfg(feature = "opentelemetry")]
    {
        match result.as_ref() {
            Ok(r) => {
                span_ref.set_status(Status::Ok)
            },
            Err(e) => {
                span_ref.record_error(e);
                span_ref.set_status(Status::Error { description: Cow::from(e.to_string()) })
            }
        }
    }

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

    #[cfg(feature = "opentelemetry")]
    {
        let status_code = response.as_ref().unwrap().status().as_u16();

        span_ref.set_attribute(KeyValue::new(
            HTTP_RESPONSE_STATUS_CODE,
            status_code as i64,
        ));
        span_ref.end();
    }

    response
}

// Utility function to extract the context from the incoming request headers
#[cfg(feature = "opentelemetry")]
fn extract_context_from_request(req: &Request<Incoming>) -> Context {
    global::get_text_map_propagator(|propagator| {
        propagator.extract(&HeaderExtractor(req.headers()))
    })
}