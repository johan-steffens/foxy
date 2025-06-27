// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Load testing for Foxy API Gateway

use foxy::Foxy;
use serde_json::json;
use serial_test::serial;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Semaphore;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

mod common;
use common::{TestConfigProvider, TestRoute, init_test_logging};

/// Load test configuration
#[derive(Debug, Clone)]
pub struct LoadTestConfig {
    /// Number of concurrent requests
    pub concurrent_requests: usize,
    /// Total number of requests to send
    pub total_requests: usize,
    /// Duration to run the test
    pub duration: Duration,
    /// Request timeout
    pub request_timeout: Duration,
}

impl Default for LoadTestConfig {
    fn default() -> Self {
        Self {
            concurrent_requests: 10,
            total_requests: 1000,
            duration: Duration::from_secs(30),
            request_timeout: Duration::from_secs(5),
        }
    }
}

/// Load test results
#[derive(Debug)]
pub struct LoadTestResults {
    /// Total requests sent
    pub total_requests: usize,
    /// Successful requests
    pub successful_requests: usize,
    /// Failed requests
    pub failed_requests: usize,
    /// Total duration
    pub total_duration: Duration,
    /// Requests per second
    pub requests_per_second: f64,
    /// Average response time
    pub avg_response_time: Duration,
    /// Minimum response time
    pub min_response_time: Duration,
    /// Maximum response time
    pub max_response_time: Duration,
    /// 95th percentile response time
    pub p95_response_time: Duration,
    /// 99th percentile response time
    pub p99_response_time: Duration,
}

impl LoadTestResults {
    pub fn print_summary(&self) {
        println!("\n=== Load Test Results ===");
        println!("Total Requests: {}", self.total_requests);
        println!("Successful: {}", self.successful_requests);
        println!("Failed: {}", self.failed_requests);
        println!(
            "Success Rate: {:.2}%",
            (self.successful_requests as f64 / self.total_requests as f64) * 100.0
        );
        println!("Duration: {:.2}s", self.total_duration.as_secs_f64());
        println!("Requests/sec: {:.2}", self.requests_per_second);
        println!(
            "Avg Response Time: {:.2}ms",
            self.avg_response_time.as_millis()
        );
        println!(
            "Min Response Time: {:.2}ms",
            self.min_response_time.as_millis()
        );
        println!(
            "Max Response Time: {:.2}ms",
            self.max_response_time.as_millis()
        );
        println!(
            "95th Percentile: {:.2}ms",
            self.p95_response_time.as_millis()
        );
        println!(
            "99th Percentile: {:.2}ms",
            self.p99_response_time.as_millis()
        );
    }
}

/// Run a load test against the proxy
pub async fn run_load_test(proxy_url: &str, path: &str, config: LoadTestConfig) -> LoadTestResults {
    let client = reqwest::Client::builder()
        .timeout(config.request_timeout)
        .build()
        .expect("Failed to create HTTP client");

    let semaphore = Arc::new(Semaphore::new(config.concurrent_requests));
    let mut tasks = Vec::new();
    let mut response_times = Vec::new();

    let start_time = Instant::now();
    let url = format!("{}{}", proxy_url, path);

    for i in 0..config.total_requests {
        let client = client.clone();
        let url = url.clone();
        let semaphore = semaphore.clone();

        let task = tokio::spawn(async move {
            let _permit = semaphore.acquire().await.unwrap();

            let request_start = Instant::now();
            let result = client.get(&url).send().await;
            let request_duration = request_start.elapsed();

            match result {
                Ok(response) => {
                    let success = response.status().is_success();
                    (success, request_duration, i)
                }
                Err(_) => (false, request_duration, i),
            }
        });

        tasks.push(task);

        // Add small delay to avoid overwhelming the system
        if i % 100 == 0 && i > 0 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    // Wait for all requests to complete
    let mut successful_requests = 0;
    let mut failed_requests = 0;

    for task in tasks {
        match task.await {
            Ok((success, duration, _)) => {
                response_times.push(duration);
                if success {
                    successful_requests += 1;
                } else {
                    failed_requests += 1;
                }
            }
            Err(_) => {
                failed_requests += 1;
            }
        }
    }

    let total_duration = start_time.elapsed();

    // Calculate statistics
    response_times.sort();
    let avg_response_time = Duration::from_nanos(
        (response_times.iter().map(|d| d.as_nanos()).sum::<u128>() / response_times.len() as u128)
            as u64,
    );
    let min_response_time = response_times.first().copied().unwrap_or_default();
    let max_response_time = response_times.last().copied().unwrap_or_default();

    let p95_index = (response_times.len() as f64 * 0.95) as usize;
    let p99_index = (response_times.len() as f64 * 0.99) as usize;
    let p95_response_time = response_times.get(p95_index).copied().unwrap_or_default();
    let p99_response_time = response_times.get(p99_index).copied().unwrap_or_default();

    let requests_per_second = config.total_requests as f64 / total_duration.as_secs_f64();

    LoadTestResults {
        total_requests: config.total_requests,
        successful_requests,
        failed_requests,
        total_duration,
        requests_per_second,
        avg_response_time,
        min_response_time,
        max_response_time,
        p95_response_time,
        p99_response_time,
    }
}

#[tokio::test]
#[ignore]
#[serial]
async fn test_basic_load() {
    init_test_logging();

    // Start a mock upstream server
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/api/test"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({"message": "Hello, World!"}))
                .insert_header("content-type", "application/json"),
        )
        .mount(&mock_server)
        .await;

    // Configure the proxy with a specific port for this test
    let config = TestConfigProvider::new("load_test")
        .with_value("server.port", 8080)
        .with_routes(vec![
            TestRoute::new(&mock_server.uri()).with_path("/api/test"),
        ]);

    let foxy = Foxy::loader()
        .with_provider(config)
        .build()
        .await
        .expect("Failed to build Foxy instance");

    let server_handle = tokio::spawn(async move { foxy.start().await });

    // Give the server time to start
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Run load test
    let load_config = LoadTestConfig {
        concurrent_requests: 5,
        total_requests: 100,
        duration: Duration::from_secs(10),
        request_timeout: Duration::from_secs(2),
    };

    let results = run_load_test("http://127.0.0.1:8080", "/api/test", load_config).await;

    results.print_summary();

    // Assertions
    assert!(
        results.successful_requests > 0,
        "Should have some successful requests"
    );
    assert!(
        results.requests_per_second > 0.0,
        "Should have positive RPS"
    );
    assert!(
        results.avg_response_time < Duration::from_secs(1),
        "Average response time should be reasonable"
    );

    // Success rate should be high for a simple test
    let success_rate = results.successful_requests as f64 / results.total_requests as f64;
    assert!(
        success_rate > 0.9,
        "Success rate should be > 90%, got {:.2}%",
        success_rate * 100.0
    );

    server_handle.abort();
}

#[tokio::test]
#[ignore]
#[serial]
async fn test_high_concurrency_load() {
    init_test_logging();

    // Start a mock upstream server
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/api/concurrent"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({"timestamp": "2024-01-01T00:00:00Z"}))
                .insert_header("content-type", "application/json"),
        )
        .mount(&mock_server)
        .await;

    // Configure the proxy with a specific port for this test
    let config = TestConfigProvider::new("concurrent_test")
        .with_value("server.port", 8080)
        .with_routes(vec![
            TestRoute::new(&mock_server.uri()).with_path("/api/concurrent"),
        ]);

    let foxy = Foxy::loader()
        .with_provider(config)
        .build()
        .await
        .expect("Failed to build Foxy instance");

    let server_handle = tokio::spawn(async move { foxy.start().await });

    tokio::time::sleep(Duration::from_millis(200)).await;

    // Run high concurrency test
    let load_config = LoadTestConfig {
        concurrent_requests: 50,
        total_requests: 500,
        duration: Duration::from_secs(15),
        request_timeout: Duration::from_secs(3),
    };

    let results = run_load_test("http://127.0.0.1:8080", "/api/concurrent", load_config).await;

    results.print_summary();

    // Assertions for high concurrency
    assert!(
        results.successful_requests > 0,
        "Should handle concurrent requests"
    );
    assert!(
        results.requests_per_second > 10.0,
        "Should maintain reasonable throughput"
    );

    // Allow for some failures under high load
    let success_rate = results.successful_requests as f64 / results.total_requests as f64;
    assert!(
        success_rate > 0.8,
        "Success rate should be > 80% under high load, got {:.2}%",
        success_rate * 100.0
    );

    server_handle.abort();
}

#[tokio::test]
#[ignore]
#[serial]
async fn test_sustained_load() {
    init_test_logging();

    // Start a mock upstream server
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/api/sustained"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({"data": "sustained load test"}))
                .insert_header("content-type", "application/json"),
        )
        .mount(&mock_server)
        .await;

    // Configure the proxy with a specific port for this test
    let config = TestConfigProvider::new("sustained_test")
        .with_value("server.port", 8080)
        .with_routes(vec![
            TestRoute::new(&mock_server.uri()).with_path("/api/sustained"),
        ]);

    let foxy = Foxy::loader()
        .with_provider(config)
        .build()
        .await
        .expect("Failed to build Foxy instance");

    let server_handle = tokio::spawn(async move { foxy.start().await });

    tokio::time::sleep(Duration::from_millis(200)).await;

    // Run sustained load test
    let load_config = LoadTestConfig {
        concurrent_requests: 20,
        total_requests: 1000,
        duration: Duration::from_secs(30),
        request_timeout: Duration::from_secs(5),
    };

    let results = run_load_test("http://127.0.0.1:8080", "/api/sustained", load_config).await;

    results.print_summary();

    // Assertions for sustained load
    assert!(
        results.successful_requests > 0,
        "Should handle sustained load"
    );
    assert!(
        results.requests_per_second > 5.0,
        "Should maintain throughput over time"
    );

    // Check that response times don't degrade too much
    assert!(
        results.p95_response_time < Duration::from_secs(2),
        "95th percentile should be reasonable: {:?}",
        results.p95_response_time
    );

    server_handle.abort();
}
