// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! End-to-end integration tests for Foxy API Gateway

use foxy::Foxy;
use serde_json::json;
use std::time::Duration;
use tokio::time::timeout;
use warp::Filter;

mod common;
use common::{TestConfigProvider, init_test_logging};

/// Start a mock HTTP server that mimics httpbin.org behavior
async fn start_mock_server() -> (tokio::task::JoinHandle<()>, u16) {
    // Create mock endpoints that return httpbin-like responses
    let get_route = warp::path("get")
        .and(warp::get())
        .and(warp::header::headers_cloned())
        .map(|headers: warp::http::HeaderMap| {
            println!("🔍 Mock server received GET /get request");
            println!("📋 Headers: {headers:?}");

            // Check if request came through Foxy proxy by looking for forwarded headers
            let via_foxy = headers.get("x-forwarded-for").is_some()
                || headers
                    .get("user-agent")
                    .map(|v| v.to_str().unwrap_or(""))
                    .unwrap_or("")
                    .contains("reqwest");

            warp::reply::json(&json!({
                "args": {},
                "headers": {
                    "Host": "httpbin.org",
                    "User-Agent": "reqwest/0.11",
                    "Via-Foxy": via_foxy
                },
                "origin": "127.0.0.1",
                "url": "https://httpbin.org/get",
                "proxy_test": "✅ Request processed by mock server"
            }))
        });

    let post_route = warp::path("post")
        .and(warp::post())
        .and(warp::body::bytes())
        .map(|_body: bytes::Bytes| {
            println!("🔍 Mock server received POST /post request");
            warp::reply::json(&json!({
                "args": {},
                "data": "",
                "files": {},
                "form": {},
                "headers": {
                    "Host": "httpbin.org",
                    "User-Agent": "reqwest/0.11"
                },
                "json": null,
                "origin": "127.0.0.1",
                "url": "https://httpbin.org/post"
            }))
        });

    let put_route = warp::path("put")
        .and(warp::put())
        .and(warp::body::bytes())
        .map(|_body: bytes::Bytes| {
            println!("🔍 Mock server received PUT /put request");
            warp::reply::json(&json!({
                "args": {},
                "data": "",
                "files": {},
                "form": {},
                "headers": {
                    "Host": "httpbin.org",
                    "User-Agent": "reqwest/0.11"
                },
                "json": null,
                "origin": "127.0.0.1",
                "url": "https://httpbin.org/put"
            }))
        });

    let delete_route = warp::path("delete")
        .and(warp::delete())
        .and(warp::body::bytes())
        .map(|_body: bytes::Bytes| {
            println!("🔍 Mock server received DELETE /delete request");
            warp::reply::json(&json!({
                "args": {},
                "data": "",
                "files": {},
                "form": {},
                "headers": {
                    "Host": "httpbin.org",
                    "User-Agent": "reqwest/0.11"
                },
                "json": null,
                "origin": "127.0.0.1",
                "url": "https://httpbin.org/delete"
            }))
        });

    let anything_route = warp::path("anything")
        .and(warp::path::tail())
        .and(warp::header::headers_cloned())
        .map(|tail: warp::path::Tail, headers: warp::http::HeaderMap| {
            println!(
                "🔍 Mock server received GET /anything/{} request",
                tail.as_str()
            );
            println!("📋 Headers: {headers:?}");

            warp::reply::json(&json!({
                "args": {},
                "data": "",
                "files": {},
                "form": {},
                "headers": {
                    "Host": "httpbin.org",
                    "User-Agent": "reqwest/0.11"
                },
                "json": null,
                "method": "GET",
                "origin": "127.0.0.1",
                "url": format!("https://httpbin.org/anything/{}", tail.as_str()),
                "proxy_test": "✅ Request processed by mock server"
            }))
        });

    let routes = get_route
        .or(post_route)
        .or(put_route)
        .or(delete_route)
        .or(anything_route);

    // Start server on a random available port
    let (addr, server) = warp::serve(routes).bind_ephemeral(([127, 0, 0, 1], 0));

    let port = addr.port();
    let handle = tokio::spawn(server);

    // Give the server a moment to start
    tokio::time::sleep(Duration::from_millis(100)).await;

    (handle, port)
}

/// Create a test configuration that points to the local mock server
fn create_test_config(mock_server_port: u16) -> serde_json::Value {
    json!({
        "server": {
            "host": "127.0.0.1",
            "port": 6868
        },
        "proxy": {
            "timeout": 30,
            "logging": {
                "structured": false,
                "format": "terminal",
                "level": "warn"
            }
        },
        "routes": [
            {
                "id": "httpbin-get",
                "target": format!("http://127.0.0.1:{mock_server_port}"),
                "filters": [
                    {
                        "type": "path_rewrite",
                        "config": {
                            "pattern": "^/$",
                            "replacement": "/get"
                        }
                    }
                ],
                "priority": 100,
                "predicates": [
                    {
                        "type_": "path",
                        "config": {
                            "pattern": "/"
                        }
                    },
                    {
                        "type_": "method",
                        "config": {
                            "methods": ["GET"]
                        }
                    }
                ]
            },
            {
                "id": "httpbin-post",
                "target": format!("http://127.0.0.1:{mock_server_port}"),
                "filters": [
                    {
                        "type": "path_rewrite",
                        "config": {
                            "pattern": "^/$",
                            "replacement": "/post"
                        }
                    }
                ],
                "priority": 90,
                "predicates": [
                    {
                        "type_": "path",
                        "config": {
                            "pattern": "/"
                        }
                    },
                    {
                        "type_": "method",
                        "config": {
                            "methods": ["POST"]
                        }
                    }
                ]
            },
            {
                "id": "httpbin-put",
                "target": format!("http://127.0.0.1:{mock_server_port}"),
                "filters": [
                    {
                        "type": "path_rewrite",
                        "config": {
                            "pattern": "^/$",
                            "replacement": "/put"
                        }
                    }
                ],
                "priority": 80,
                "predicates": [
                    {
                        "type_": "path",
                        "config": {
                            "pattern": "/"
                        }
                    },
                    {
                        "type_": "method",
                        "config": {
                            "methods": ["PUT"]
                        }
                    }
                ]
            },
            {
                "id": "httpbin-delete",
                "target": format!("http://127.0.0.1:{}", mock_server_port),
                "filters": [
                    {
                        "type": "path_rewrite",
                        "config": {
                            "pattern": "^/$",
                            "replacement": "/delete"
                        }
                    }
                ],
                "priority": 70,
                "predicates": [
                    {
                        "type_": "path",
                        "config": {
                            "pattern": "/"
                        }
                    },
                    {
                        "type_": "method",
                        "config": {
                            "methods": ["DELETE"]
                        }
                    }
                ]
            },
            {
                "id": "httpbin-anything",
                "target": format!("http://127.0.0.1:{}", mock_server_port),
                "filters": [],
                "priority": 50,
                "predicates": [
                    {
                        "type_": "path",
                        "config": {
                            "pattern": "/anything/*"
                        }
                    }
                ]
            }
        ]
    })
}

#[tokio::test]
#[serial_test::serial]
async fn test_basic_proxy_functionality() {
    init_test_logging();

    // Start mock server
    let (mock_handle, mock_port) = start_mock_server().await;

    // Create test configuration with mock server
    let config = create_test_config(mock_port);
    let config_provider = TestConfigProvider::from_json(config);

    // Build Foxy with test configuration
    let foxy = Foxy::loader()
        .with_provider(config_provider)
        .build()
        .await
        .expect("Failed to build Foxy instance");

    // Start the proxy server in the background
    let server_handle = tokio::spawn(async move { foxy.start().await });

    // Give the server time to start
    tokio::time::sleep(Duration::from_millis(1000)).await;

    // Make a request through the proxy to mock server
    let client = reqwest::Client::new();
    let response = timeout(
        Duration::from_secs(10),
        client.get("http://127.0.0.1:8080/").send(),
    )
    .await;

    // Verify the response
    match response {
        Ok(Ok(resp)) => {
            assert_eq!(resp.status(), 200);
            let body = resp.text().await.expect("Failed to read body");
            assert!(body.contains("httpbin") || body.contains("origin") || body.contains("url"));
        }
        Ok(Err(e)) => panic!("Request failed: {e}"),
        Err(_) => panic!("Request timed out"),
    }

    // Clean up
    server_handle.abort();
    mock_handle.abort();

    // Give time for cleanup
    tokio::time::sleep(Duration::from_millis(500)).await;
}

#[tokio::test]
#[serial_test::serial]
async fn test_anything_endpoint() {
    init_test_logging();

    // Start mock server
    let (mock_handle, mock_port) = start_mock_server().await;

    // Create test configuration with mock server
    let config = create_test_config(mock_port);
    let config_provider = TestConfigProvider::from_json(config);

    // Build Foxy with test configuration
    let foxy = Foxy::loader()
        .with_provider(config_provider)
        .build()
        .await
        .expect("Failed to build Foxy instance");

    let server_handle = tokio::spawn(async move { foxy.start().await });

    tokio::time::sleep(Duration::from_millis(1000)).await;

    // Make request to mock anything endpoint
    println!("🚀 Making request to Foxy proxy at http://127.0.0.1:8080/anything/test");
    println!("📡 Mock server running on port: {}", mock_port);

    let client = reqwest::Client::new();
    let response = timeout(
        Duration::from_secs(10),
        client.get("http://127.0.0.1:8080/anything/test").send(),
    )
    .await;

    // Verify the response
    match response {
        Ok(Ok(resp)) => {
            println!("✅ Response status: {}", resp.status());
            assert_eq!(resp.status(), 200);
            let body = resp.text().await.expect("Failed to read body");
            println!("📄 Response body: {}", body);
            assert!(body.contains("httpbin") || body.contains("origin") || body.contains("url"));

            // Verify it contains our proxy test marker
            assert!(
                body.contains("proxy_test"),
                "Response should contain proxy_test marker from mock server"
            );
        }
        Ok(Err(e)) => panic!("Request failed: {e}"),
        Err(_) => panic!("Request timed out"),
    }

    server_handle.abort();
    mock_handle.abort();

    // Give time for cleanup
    tokio::time::sleep(Duration::from_millis(500)).await;
}

#[tokio::test]
#[serial_test::serial]
async fn test_post_method() {
    init_test_logging();

    // Start mock server
    let (mock_handle, mock_port) = start_mock_server().await;

    // Create test configuration with mock server
    let config = create_test_config(mock_port);
    let config_provider = TestConfigProvider::from_json(config);

    // Build Foxy with test configuration
    let foxy = Foxy::loader()
        .with_provider(config_provider)
        .build()
        .await
        .expect("Failed to build Foxy instance");

    let server_handle = tokio::spawn(async move { foxy.start().await });

    tokio::time::sleep(Duration::from_millis(1000)).await;

    // Make POST request to mock server
    let client = reqwest::Client::new();
    let response = timeout(
        Duration::from_secs(10),
        client.post("http://127.0.0.1:8080/").send(),
    )
    .await;

    // Verify the response
    match response {
        Ok(Ok(resp)) => {
            assert_eq!(resp.status(), 200);
            let body = resp.text().await.expect("Failed to read body");
            assert!(body.contains("httpbin") || body.contains("origin") || body.contains("url"));
        }
        Ok(Err(e)) => panic!("Request failed: {e}"),
        Err(_) => panic!("Request timed out"),
    }

    server_handle.abort();
    mock_handle.abort();

    // Give time for cleanup
    tokio::time::sleep(Duration::from_millis(500)).await;
}

#[tokio::test]
#[serial_test::serial]
async fn test_put_method() {
    init_test_logging();

    // Start mock server
    let (mock_handle, mock_port) = start_mock_server().await;

    // Create test configuration with mock server
    let config = create_test_config(mock_port);
    let config_provider = TestConfigProvider::from_json(config);

    // Build Foxy with test configuration
    let foxy = Foxy::loader()
        .with_provider(config_provider)
        .build()
        .await
        .expect("Failed to build Foxy instance");

    let server_handle = tokio::spawn(async move { foxy.start().await });

    tokio::time::sleep(Duration::from_millis(1000)).await;

    let client = reqwest::Client::new();

    // Test PUT / (should route to mock server /put via path rewrite)
    let response = timeout(
        Duration::from_secs(10),
        client.put("http://127.0.0.1:8080/").send(),
    )
    .await;

    match response {
        Ok(Ok(resp)) => {
            assert_eq!(resp.status(), 200);
            let body = resp.text().await.unwrap();
            assert!(body.contains("httpbin") || body.contains("origin") || body.contains("url"));
        }
        Ok(Err(e)) => panic!("Request failed: {e}"),
        Err(_) => panic!("Request timed out"),
    }

    server_handle.abort();
    mock_handle.abort();

    // Give time for cleanup
    tokio::time::sleep(Duration::from_millis(500)).await;
}

#[tokio::test]
#[serial_test::serial]
async fn test_delete_method() {
    init_test_logging();

    // Start mock server
    let (mock_handle, mock_port) = start_mock_server().await;

    // Create test configuration with mock server
    let config = create_test_config(mock_port);
    let config_provider = TestConfigProvider::from_json(config);

    // Build Foxy with test configuration
    let foxy = Foxy::loader()
        .with_provider(config_provider)
        .build()
        .await
        .expect("Failed to build Foxy instance");

    let server_handle = tokio::spawn(async move { foxy.start().await });

    tokio::time::sleep(Duration::from_millis(1000)).await;

    let client = reqwest::Client::new();

    // Test DELETE / (should route to mock server /delete via path rewrite)
    let response = timeout(
        Duration::from_secs(10),
        client.delete("http://127.0.0.1:8080/").send(),
    )
    .await;

    match response {
        Ok(Ok(resp)) => {
            assert_eq!(resp.status(), 200);
            let body = resp.text().await.expect("Failed to read body");
            assert!(body.contains("httpbin") || body.contains("origin") || body.contains("url"));
        }
        Ok(Err(e)) => panic!("Request failed: {e}"),
        Err(_) => panic!("Request timed out"),
    }

    server_handle.abort();
    mock_handle.abort();

    // Give time for cleanup
    tokio::time::sleep(Duration::from_millis(500)).await;
}
