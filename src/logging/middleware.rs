// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! HTTP middleware for request/response logging with trace context.

use hyper::{Request, Response, StatusCode};
use std::task::{Context, Poll};
use std::pin::Pin;
use std::future::Future;
use futures_util::ready;
use std::time::{Instant, Duration};
use crate::logging::structured::{RequestInfo, generate_trace_id};
use crate::logging::config::LoggingConfig;
use slog_scope;
use std::sync::Arc;
use std::net::SocketAddr;

/// Middleware for request/response logging with trace context
#[derive(Clone)]
pub struct LoggingMiddleware {
    config: Arc<LoggingConfig>,
}

impl LoggingMiddleware {
    /// Create a new logging middleware
    pub fn new(config: LoggingConfig) -> Self {
        Self {
            config: Arc::new(config),
        }
    }
    
    /// Process a request and add trace context
    pub async fn process<B>(
        &self,
        req: Request<B>,
        remote_addr: Option<SocketAddr>,
    ) -> (Request<B>, RequestInfo) {
        let method = req.method().to_string();
        let path = req.uri().path().to_string();
        let remote_addr_str = remote_addr
            .map(|addr| addr.to_string())
            .unwrap_or_else(|| "unknown".to_string());
        
        let user_agent = req
            .headers()
            .get(hyper::header::USER_AGENT)
            .and_then(|h| h.to_str().ok())
            .unwrap_or("unknown")
            .to_string();
        
        // Check for existing trace ID in headers if propagation is enabled
        let trace_id = if self.config.propagate_trace_id {
            req.headers()
                .get(&self.config.trace_id_header)
                .and_then(|h| h.to_str().ok())
                .map(|s| s.to_string())
                .unwrap_or_else(generate_trace_id)
        } else {
            generate_trace_id()
        };
        
        let request_info = RequestInfo {
            trace_id,
            method,
            path,
            remote_addr: remote_addr_str,
            user_agent,
            start_time_ms: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis(),
        };
        
        // Log the incoming request with trace context
        if self.config.structured {
            let logger = slog_scope::logger();
            scrate::info!(logger, "Request received";
                "trace_id" => &request_info.trace_id,
                "method" => &request_info.method,
                "path" => &request_info.path,
                "remote_addr" => &request_info.remote_addr,
                "user_agent" => &request_info.user_agent
            );
        } else {
            crate::info!(
                "Request received: {} {} from {} (trace_id: {})",
                request_info.method,
                request_info.path,
                request_info.remote_addr,
                request_info.trace_id
            );
        }
        
        (req, request_info)
    }
    
    /// Log the response with timing information
    pub fn log_response<B>(
        &self,
        response: &Response<B>,
        request_info: &RequestInfo,
        upstream_duration: Option<Duration>,
    ) {
        let status = response.status().as_u16();
        let elapsed_ms = request_info.elapsed_ms();
        let upstream_ms = upstream_duration
            .map(|d| d.as_millis())
            .unwrap_or(0);
        let internal_ms = elapsed_ms.saturating_sub(upstream_ms);
        
        if self.config.structured {
            let logger = slog_scope::logger();
            scrate::info!(logger, "Response completed";
                "trace_id" => &request_info.trace_id,
                "method" => &request_info.method,
                "path" => &request_info.path,
                "status" => status,
                "elapsed_ms" => elapsed_ms,
                "upstream_ms" => upstream_ms,
                "internal_ms" => internal_ms
            );
        } else {
            crate::info!(
                "[timing] {} {} -> {} | total={}ms upstream={}ms internal={}ms (trace_id: {})",
                request_info.method,
                request_info.path,
                status,
                elapsed_ms,
                upstream_ms,
                internal_ms,
                request_info.trace_id
            );
        }
    }
}

/// Future that wraps a response future and adds trace ID header
pub struct TracedResponseFuture<F> {
    inner: F,
    trace_id: String,
    trace_header: String,
    include_trace_id: bool,
}

impl<F, B, E> Future for TracedResponseFuture<F>
where
    F: Future<Output = Result<Response<B>, E>> + Unpin,
{
    type Output = Result<Response<B>, E>;
    
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let result = ready!(Pin::new(&mut self.inner).poll(cx));
        
        Poll::Ready(match result {
            Ok(mut response) => {
                // Add trace ID header to response if enabled
                if self.include_trace_id {
                    response.headers_mut().insert(
                        self.trace_header.parse().unwrap(),
                        self.trace_id.parse().unwrap(),
                    );
                }
                Ok(response)
            }
            Err(e) => Err(e),
        })
    }
}

/// Extension trait for response futures to add trace context
pub trait ResponseFutureExt: Sized {
    /// Add trace ID header to the response
    fn with_trace_id(
        self,
        trace_id: String,
        trace_header: String,
        include_trace_id: bool,
    ) -> TracedResponseFuture<Self>;
}

impl<F, B, E> ResponseFutureExt for F
where
    F: Future<Output = Result<Response<B>, E>> + Unpin,
{
    fn with_trace_id(
        self,
        trace_id: String,
        trace_header: String,
        include_trace_id: bool,
    ) -> TracedResponseFuture<Self> {
        TracedResponseFuture {
            inner: self,
            trace_id,
            trace_header,
            include_trace_id,
        }
    }
}

/// Future that wraps a response future and adds trace ID header
pub struct TracedResponseFuture<F> {
    inner: F,
    trace_id: String,
    trace_header: String,
    include_trace_id: bool,
}

impl<F, B, E> Future for TracedResponseFuture<F>
where
    F: Future<Output = Result<Response<B>, E>> + Unpin,
{
    type Output = Result<Response<B>, E>;
    
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let result = ready!(Pin::new(&mut self.inner).poll(cx));
        
        Poll::Ready(match result {
            Ok(mut response) => {
                // Add trace ID header to response if enabled
                if self.include_trace_id {
                    response.headers_mut().insert(
                        self.trace_header.parse().unwrap(),
                        self.trace_id.parse().unwrap(),
                    );
                }
                Ok(response)
            }
            Err(e) => Err(e),
        })
    }
}

/// Extension trait for response futures to add trace context
pub trait ResponseFutureExt: Sized {
    /// Add trace ID header to the response
    fn with_trace_id(
        self,
        trace_id: String,
        trace_header: String,
        include_trace_id: bool,
    ) -> TracedResponseFuture<Self>;
}

impl<F, B, E> ResponseFutureExt for F
where
    F: Future<Output = Result<Response<B>, E>> + Unpin,
{
    fn with_trace_id(
        self,
        trace_id: String,
        trace_header: String,
        include_trace_id: bool,
    ) -> TracedResponseFuture<Self> {
        TracedResponseFuture {
            inner: self,
            trace_id,
            trace_header,
            include_trace_id,
        }
    }
}
