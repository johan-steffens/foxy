// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

#[cfg(test)]
mod tests {
    use crate::{
        HttpMethod, ProxyRequest, ProxyResponse,
        RequestContext, ResponseContext
    };
    use std::sync::Arc;
    use tokio::sync::RwLock;

    #[test]
    fn test_http_method_from() {
        assert_eq!(HttpMethod::from(&reqwest::Method::GET), HttpMethod::Get);
        assert_eq!(HttpMethod::from(&reqwest::Method::POST), HttpMethod::Post);
        assert_eq!(HttpMethod::from(&reqwest::Method::PUT), HttpMethod::Put);
        assert_eq!(HttpMethod::from(&reqwest::Method::DELETE), HttpMethod::Delete);
        assert_eq!(HttpMethod::from(&reqwest::Method::HEAD), HttpMethod::Head);
        assert_eq!(HttpMethod::from(&reqwest::Method::OPTIONS), HttpMethod::Options);
        assert_eq!(HttpMethod::from(&reqwest::Method::PATCH), HttpMethod::Patch);
        assert_eq!(HttpMethod::from(&reqwest::Method::TRACE), HttpMethod::Trace);
        assert_eq!(HttpMethod::from(&reqwest::Method::CONNECT), HttpMethod::Connect);
    }

    #[test]
    fn test_http_method_to_string() {
        assert_eq!(HttpMethod::Get.to_string(), "GET");
        assert_eq!(HttpMethod::Post.to_string(), "POST");
        assert_eq!(HttpMethod::Put.to_string(), "PUT");
        assert_eq!(HttpMethod::Delete.to_string(), "DELETE");
        assert_eq!(HttpMethod::Head.to_string(), "HEAD");
        assert_eq!(HttpMethod::Options.to_string(), "OPTIONS");
        assert_eq!(HttpMethod::Patch.to_string(), "PATCH");
        assert_eq!(HttpMethod::Trace.to_string(), "TRACE");
        assert_eq!(HttpMethod::Connect.to_string(), "CONNECT");
    }

    #[test]
    fn test_request_context() {
        let mut context = RequestContext::default();

        // Test attribute manipulation
        context.attributes.insert("key1".to_string(), serde_json::json!("value1"));
        context.attributes.insert("key2".to_string(), serde_json::json!(42));

        assert_eq!(context.attributes.get("key1").unwrap(), &serde_json::json!("value1"));
        assert_eq!(context.attributes.get("key2").unwrap(), &serde_json::json!(42));
    }

    #[test]
    fn test_response_context() {
        let mut context = ResponseContext::default();

        // Test attribute manipulation
        context.attributes.insert("key1".to_string(), serde_json::json!("value1"));
        context.attributes.insert("key2".to_string(), serde_json::json!(42));

        assert_eq!(context.attributes.get("key1").unwrap(), &serde_json::json!("value1"));
        assert_eq!(context.attributes.get("key2").unwrap(), &serde_json::json!(42));
    }

    #[tokio::test]
    async fn test_proxy_request() {
        let context = Arc::new(RwLock::new(RequestContext::default()));
        let mut request = ProxyRequest {
            method: HttpMethod::Get,
            path: "/test".to_string(),
            query: Some("param=value".to_string()),
            headers: reqwest::header::HeaderMap::new(),
            body: reqwest::Body::from(Vec::new()),
            context: context.clone(),
            custom_target: Option::Some("http://test.co.za".to_string()),
        };

        // Test context manipulation
        {
            let mut ctx = request.context.write().await;
            ctx.attributes.insert("test".to_string(), serde_json::json!("value"));
        }

        let ctx = request.context.read().await;
        assert_eq!(ctx.attributes.get("test").unwrap(), &serde_json::json!("value"));
    }

    #[tokio::test]
    async fn test_proxy_response() {
        let context = Arc::new(RwLock::new(ResponseContext::default()));
        let mut response = ProxyResponse {
            status: 200,
            headers: reqwest::header::HeaderMap::new(),
            body: reqwest::Body::from(Vec::new()),
            context: context.clone(),
        };

        // Test context manipulation
        {
            let mut ctx = response.context.write().await;
            ctx.attributes.insert("test".to_string(), serde_json::json!("value"));
        }

        let ctx = response.context.read().await;
        assert_eq!(ctx.attributes.get("test").unwrap(), &serde_json::json!("value"));
    }
}
