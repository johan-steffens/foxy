use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming as IncomingBody;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use std::{
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;

#[derive(Debug)]
pub struct HealthServer {
    is_ready: Arc<AtomicBool>,
    _handle: JoinHandle<()>,
}

impl HealthServer {
    pub fn new(port: u16) -> Self {
        let is_ready = Arc::new(AtomicBool::new(false));
        let ready_clone = is_ready.clone();

        let handle = tokio::spawn(async move {
            let addr = SocketAddr::from(([0, 0, 0, 0], port));
            let listener = TcpListener::bind(addr)
                .await
                .expect("Health server bind failed");

            loop {
                let (stream, _) = match listener.accept().await {
                    Ok(s) => s,
                    Err(e) => {
                        eprintln!("Health server accept failed: {e}");
                        continue;
                    }
                };

                let ready = ready_clone.clone();
                tokio::spawn(async move {
                    let io = TokioIo::new(stream);

                    let service = service_fn(move |req: Request<IncomingBody>| {
                        let ready = ready.clone();
                        async move {
                            let map_err =
                                |_: std::convert::Infallible| std::io::Error::other("error");

                            let response = match req.uri().path() {
                                "/health" => {
                                    Response::new(Full::new(Bytes::from("OK")).map_err(map_err))
                                }
                                "/ready" => {
                                    if ready.load(Ordering::Relaxed) {
                                        Response::new(
                                            Full::new(Bytes::from("READY")).map_err(map_err),
                                        )
                                    } else {
                                        Response::builder()
                                            .status(503)
                                            .body(
                                                Full::new(Bytes::from("NOT READY"))
                                                    .map_err(map_err),
                                            )
                                            .unwrap()
                                    }
                                }
                                _ => Response::builder()
                                    .status(404)
                                    .body(Full::new(Bytes::from("Not Found")).map_err(map_err))
                                    .unwrap(),
                            };
                            Ok::<_, std::io::Error>(response)
                        }
                    });

                    let builder = hyper_util::server::conn::auto::Builder::new(
                        hyper_util::rt::TokioExecutor::new(),
                    );
                    let conn = builder.serve_connection(io, service);

                    if let Err(err) = conn.await {
                        eprintln!("Health server connection error: {err}");
                    }
                });
            }
        });

        Self {
            is_ready,
            _handle: handle,
        }
    }

    pub fn set_ready(&self) {
        self.is_ready.store(true, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tokio::time::timeout;

    async fn get_available_port() -> u16 {
        // Use port 0 to let the OS assign an available port
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        port
    }

    async fn make_request(
        port: u16,
        path: &str,
    ) -> Result<(u16, String), Box<dyn std::error::Error + Send + Sync>> {
        let url = format!("http://127.0.0.1:{port}{path}");
        let response = reqwest::get(&url).await?;
        let status = response.status().as_u16();
        let body = response.text().await?;
        Ok((status, body))
    }

    #[tokio::test]
    async fn test_health_server_creation() {
        let port = get_available_port().await;
        let health_server = HealthServer::new(port);

        // Verify the server was created
        assert!(!health_server.is_ready.load(Ordering::Relaxed));

        // Give the server a moment to start
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    #[tokio::test]
    async fn test_health_endpoint() {
        let port = get_available_port().await;
        let _health_server = HealthServer::new(port);

        // Give the server time to start
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Test health endpoint
        let result = timeout(Duration::from_secs(5), make_request(port, "/health")).await;
        assert!(result.is_ok());

        let (status, body) = result.unwrap().unwrap();
        assert_eq!(status, 200);
        assert_eq!(body, "OK");
    }

    #[tokio::test]
    async fn test_ready_endpoint_not_ready() {
        let port = get_available_port().await;
        let health_server = HealthServer::new(port);

        // Give the server time to start
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Test ready endpoint when not ready
        let result = timeout(Duration::from_secs(5), make_request(port, "/ready")).await;
        assert!(result.is_ok());

        let (status, body) = result.unwrap().unwrap();
        assert_eq!(status, 503);
        assert_eq!(body, "NOT READY");

        // Verify is_ready is still false
        assert!(!health_server.is_ready.load(Ordering::Relaxed));
    }

    #[tokio::test]
    async fn test_ready_endpoint_ready() {
        let port = get_available_port().await;
        let health_server = HealthServer::new(port);

        // Give the server time to start
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Set ready
        health_server.set_ready();
        assert!(health_server.is_ready.load(Ordering::Relaxed));

        // Test ready endpoint when ready
        let result = timeout(Duration::from_secs(5), make_request(port, "/ready")).await;
        assert!(result.is_ok());

        let (status, body) = result.unwrap().unwrap();
        assert_eq!(status, 200);
        assert_eq!(body, "READY");
    }

    #[tokio::test]
    async fn test_unknown_endpoint() {
        let port = get_available_port().await;
        let _health_server = HealthServer::new(port);

        // Give the server time to start
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Test unknown endpoint
        let result = timeout(Duration::from_secs(5), make_request(port, "/unknown")).await;
        assert!(result.is_ok());

        let (status, body) = result.unwrap().unwrap();
        assert_eq!(status, 404);
        assert_eq!(body, "Not Found");
    }

    #[tokio::test]
    async fn test_multiple_endpoints() {
        let port = get_available_port().await;
        let health_server = HealthServer::new(port);

        // Give the server time to start
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Test health endpoint
        let (status, body) = timeout(Duration::from_secs(5), make_request(port, "/health"))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(status, 200);
        assert_eq!(body, "OK");

        // Test ready endpoint (not ready)
        let (status, body) = timeout(Duration::from_secs(5), make_request(port, "/ready"))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(status, 503);
        assert_eq!(body, "NOT READY");

        // Set ready and test again
        health_server.set_ready();
        let (status, body) = timeout(Duration::from_secs(5), make_request(port, "/ready"))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(status, 200);
        assert_eq!(body, "READY");

        // Test health endpoint again
        let (status, body) = timeout(Duration::from_secs(5), make_request(port, "/health"))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(status, 200);
        assert_eq!(body, "OK");
    }

    #[tokio::test]
    async fn test_concurrent_requests() {
        let port = get_available_port().await;
        let health_server = HealthServer::new(port);

        // Give the server time to start
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Make multiple concurrent requests
        let mut handles = vec![];

        for _ in 0..5 {
            let handle = tokio::spawn(async move { make_request(port, "/health").await });
            handles.push(handle);
        }

        // Wait for all requests to complete
        for handle in handles {
            let result = timeout(Duration::from_secs(5), handle).await;
            assert!(result.is_ok());
            let (status, body) = result.unwrap().unwrap().unwrap();
            assert_eq!(status, 200);
            assert_eq!(body, "OK");
        }

        // Set ready and test ready endpoint concurrently
        health_server.set_ready();

        let mut ready_handles = vec![];
        for _ in 0..3 {
            let handle = tokio::spawn(async move { make_request(port, "/ready").await });
            ready_handles.push(handle);
        }

        for handle in ready_handles {
            let result = timeout(Duration::from_secs(5), handle).await;
            assert!(result.is_ok());
            let (status, body) = result.unwrap().unwrap().unwrap();
            assert_eq!(status, 200);
            assert_eq!(body, "READY");
        }
    }

    #[tokio::test]
    async fn test_set_ready_multiple_times() {
        let port = get_available_port().await;
        let health_server = HealthServer::new(port);

        // Initially not ready
        assert!(!health_server.is_ready.load(Ordering::Relaxed));

        // Set ready multiple times
        health_server.set_ready();
        assert!(health_server.is_ready.load(Ordering::Relaxed));

        health_server.set_ready();
        assert!(health_server.is_ready.load(Ordering::Relaxed));

        health_server.set_ready();
        assert!(health_server.is_ready.load(Ordering::Relaxed));
    }

    #[tokio::test]
    async fn test_health_server_debug() {
        let port = get_available_port().await;
        let health_server = HealthServer::new(port);

        // Test Debug implementation
        let debug_str = format!("{health_server:?}");
        assert!(debug_str.contains("HealthServer"));
        assert!(debug_str.contains("is_ready"));
        assert!(debug_str.contains("_handle"));
    }
}
