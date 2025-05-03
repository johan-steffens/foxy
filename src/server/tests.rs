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
