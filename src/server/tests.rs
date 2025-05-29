// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use bytes::Bytes;
use http_body_util::Full;
use hyper::Response;
use crate::core::{ProxyResponse, ResponseContext};
use std::sync::Arc;
use tokio::sync::RwLock;

/// Helper function to convert a hyper response to a ProxyResponse (for testing)
#[allow(dead_code)]
fn convert_hyper_response(resp: Response<Full<Bytes>>) -> ProxyResponse {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{HttpMethod, ProxyRequest, ProxyResponse, RequestContext};
    use hyper::{Request, StatusCode};
    use std::time::Duration;

    #[tokio::test]
    async fn test_convert_hyper_response() {
        // Create a hyper response
        let hyper_response = Response::builder()
            .status(StatusCode::OK)
            .header("content-type", "application/json")
            .body(Full::new(Bytes::from(r#"{"result":"success"}"#)))
            .unwrap();

        // Convert to proxy response
        let proxy_response = convert_hyper_response(hyper_response);

        // Verify the conversion
        assert_eq!(proxy_response.status, 200);
        assert!(proxy_response.headers.contains_key("content-type"));
        let content_type = proxy_response.headers.get("content-type").unwrap();
        assert_eq!(content_type, "application/json");
    }
}
