use std::{net::SocketAddr, sync::{Arc, atomic::{AtomicBool, Ordering}}};
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;
use hyper::{Request, Response};
use hyper::service::{service_fn};
use hyper::body::Incoming as IncomingBody;
use hyper_util::rt::TokioIo;

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
                            let map_err = |_: std::convert::Infallible| {
                                std::io::Error::new(std::io::ErrorKind::Other, "error")
                            };
                            
                            let response = match req.uri().path() {
                                "/health" => Response::new(
                                    Full::new(Bytes::from("OK")).map_err(map_err)
                                ),
                                "/ready" => {
                                    if ready.load(Ordering::Relaxed) {
                                        Response::new(Full::new(Bytes::from("READY")).map_err(map_err))
                                    } else {
                                        Response::builder()
                                            .status(503)
                                            .body(Full::new(Bytes::from("NOT READY")).map_err(map_err))
                                            .unwrap()
                                    }
                                },
                                _ => Response::builder()
                                    .status(404)
                                    .body(Full::new(Bytes::from("Not Found")).map_err(map_err))
                                    .unwrap(),
                            };
                            Ok::<_, std::io::Error>(response)
                        }
                    });

                    let builder = hyper_util::server::conn::auto::Builder::new(hyper_util::rt::TokioExecutor::new());
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