// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

#[cfg(feature = "swagger-ui")]
mod swagger_tests {
    use crate::server::swagger::{SwaggerSource, SwaggerUIConfig, handle_swagger_request};
    use bytes::Bytes;
    use http_body_util::Empty;
    use hyper::{Method, Request};
    use serde_json;

    #[test]
    fn test_swagger_source_creation() {
        let source = SwaggerSource {
            name: "Test API".to_string(),
            url: "/api/v1/openapi.json".to_string(),
        };

        assert_eq!(source.name, "Test API");
        assert_eq!(source.url, "/api/v1/openapi.json");
    }

    #[test]
    fn test_swagger_source_serialization() {
        let source = SwaggerSource {
            name: "Test API".to_string(),
            url: "/api/v1/openapi.json".to_string(),
        };

        let json = serde_json::to_string(&source).expect("Failed to serialize SwaggerSource");
        let expected = r#"{"name":"Test API","url":"/api/v1/openapi.json"}"#;
        assert_eq!(json, expected);
    }

    #[test]
    fn test_swagger_source_deserialization() {
        let json = r#"{"name":"Test API","url":"/api/v1/openapi.json"}"#;
        let source: SwaggerSource =
            serde_json::from_str(json).expect("Failed to deserialize SwaggerSource");

        assert_eq!(source.name, "Test API");
        assert_eq!(source.url, "/api/v1/openapi.json");
    }

    #[test]
    fn test_swagger_source_with_special_characters() {
        let source = SwaggerSource {
            name: "Test API with \"quotes\" & symbols".to_string(),
            url: "/api/v1/openapi.json?param=value&other=test".to_string(),
        };

        let json = serde_json::to_string(&source).expect("Failed to serialize SwaggerSource");
        let deserialized: SwaggerSource =
            serde_json::from_str(&json).expect("Failed to deserialize SwaggerSource");

        assert_eq!(deserialized.name, source.name);
        assert_eq!(deserialized.url, source.url);
    }

    #[test]
    fn test_swagger_ui_config_default() {
        let config = SwaggerUIConfig::default();

        assert!(!config.enabled);
        assert_eq!(config.path, "/swagger-ui");
        assert!(config.sources.is_empty());
    }

    #[test]
    fn test_swagger_ui_config_custom() {
        let sources = vec![
            SwaggerSource {
                name: "API v1".to_string(),
                url: "/api/v1/openapi.json".to_string(),
            },
            SwaggerSource {
                name: "API v2".to_string(),
                url: "/api/v2/openapi.json".to_string(),
            },
        ];

        let config = SwaggerUIConfig {
            enabled: true,
            path: "/custom-swagger".to_string(),
            sources,
        };

        assert!(config.enabled);
        assert_eq!(config.path, "/custom-swagger");
        assert_eq!(config.sources.len(), 2);
        assert_eq!(config.sources[0].name, "API v1");
        assert_eq!(config.sources[1].name, "API v2");
    }

    #[test]
    fn test_swagger_ui_config_serialization() {
        let config = SwaggerUIConfig {
            enabled: true,
            path: "/swagger-ui".to_string(),
            sources: vec![SwaggerSource {
                name: "Test API".to_string(),
                url: "/api/openapi.json".to_string(),
            }],
        };

        let json = serde_json::to_string(&config).expect("Failed to serialize SwaggerUIConfig");
        assert!(json.contains("\"enabled\":true"));
        assert!(json.contains("\"path\":\"/swagger-ui\""));
        assert!(json.contains("\"sources\":["));
        assert!(json.contains("\"name\":\"Test API\""));
    }

    #[test]
    fn test_swagger_ui_config_deserialization_minimal() {
        let json = r#"{"enabled":true}"#;
        let config: SwaggerUIConfig =
            serde_json::from_str(json).expect("Failed to deserialize SwaggerUIConfig");

        assert!(config.enabled);
        assert_eq!(config.path, "/swagger-ui"); // Should use default
        assert!(config.sources.is_empty()); // Should use default
    }

    #[test]
    fn test_swagger_ui_config_deserialization_full() {
        let json = r#"{
            "enabled": true,
            "path": "/custom-path",
            "sources": [
                {"name": "API v1", "url": "/v1/openapi.json"},
                {"name": "API v2", "url": "/v2/openapi.json"}
            ]
        }"#;
        let config: SwaggerUIConfig =
            serde_json::from_str(json).expect("Failed to deserialize SwaggerUIConfig");

        assert!(config.enabled);
        assert_eq!(config.path, "/custom-path");
        assert_eq!(config.sources.len(), 2);
        assert_eq!(config.sources[0].name, "API v1");
        assert_eq!(config.sources[1].url, "/v2/openapi.json");
    }

    #[test]
    fn test_swagger_ui_config_deserialization_empty() {
        let json = r#"{}"#;
        let config: SwaggerUIConfig =
            serde_json::from_str(json).expect("Failed to deserialize SwaggerUIConfig");

        assert!(!config.enabled); // Should use default (false)
        assert_eq!(config.path, "/swagger-ui"); // Should use default
        assert!(config.sources.is_empty()); // Should use default
    }

    #[test]
    fn test_swagger_ui_config_clone() {
        let original = SwaggerUIConfig {
            enabled: true,
            path: "/test".to_string(),
            sources: vec![SwaggerSource {
                name: "Test".to_string(),
                url: "/test.json".to_string(),
            }],
        };

        let cloned = original.clone();
        assert_eq!(original.enabled, cloned.enabled);
        assert_eq!(original.path, cloned.path);
        assert_eq!(original.sources.len(), cloned.sources.len());
        assert_eq!(original.sources[0].name, cloned.sources[0].name);
    }

    #[test]
    fn test_swagger_ui_config_debug() {
        let config = SwaggerUIConfig::default();
        let debug_str = format!("{:?}", config);
        assert!(debug_str.contains("SwaggerUIConfig"));
        assert!(debug_str.contains("enabled"));
        assert!(debug_str.contains("path"));
        assert!(debug_str.contains("sources"));
    }

    // Tests for internal functions - these need to be accessed via the module
    // Since the functions are private, we'll test them through the public API

    #[tokio::test]
    async fn test_handle_swagger_request_root_path() {
        let config = SwaggerUIConfig {
            enabled: true,
            path: "/swagger-ui".to_string(),
            sources: vec![SwaggerSource {
                name: "Test API".to_string(),
                url: "/api/openapi.json".to_string(),
            }],
        };

        let req = Request::builder()
            .method(Method::GET)
            .uri("/swagger-ui")
            .body(Empty::<Bytes>::new())
            .unwrap();

        let response = handle_swagger_request(&req, &config).await.unwrap();
        assert_eq!(response.status(), 200);

        let content_type = response.headers().get("content-type").unwrap();
        assert_eq!(content_type, "text/html; charset=utf-8");
    }

    #[tokio::test]
    async fn test_handle_swagger_request_root_path_with_slash() {
        let config = SwaggerUIConfig {
            enabled: true,
            path: "/swagger-ui".to_string(),
            sources: vec![],
        };

        let req = Request::builder()
            .method(Method::GET)
            .uri("/swagger-ui/")
            .body(Empty::<Bytes>::new())
            .unwrap();

        let response = handle_swagger_request(&req, &config).await.unwrap();
        assert_eq!(response.status(), 200);

        let content_type = response.headers().get("content-type").unwrap();
        assert_eq!(content_type, "text/html; charset=utf-8");
    }

    #[tokio::test]
    async fn test_handle_swagger_request_index_html() {
        let config = SwaggerUIConfig {
            enabled: true,
            path: "/swagger-ui".to_string(),
            sources: vec![],
        };

        let req = Request::builder()
            .method(Method::GET)
            .uri("/swagger-ui/index.html")
            .body(Empty::<Bytes>::new())
            .unwrap();

        let response = handle_swagger_request(&req, &config).await.unwrap();
        assert_eq!(response.status(), 200);

        let content_type = response.headers().get("content-type").unwrap();
        assert_eq!(content_type, "text/html; charset=utf-8");
    }

    #[tokio::test]
    async fn test_handle_swagger_request_not_found() {
        let config = SwaggerUIConfig {
            enabled: true,
            path: "/swagger-ui".to_string(),
            sources: vec![],
        };

        let req = Request::builder()
            .method(Method::GET)
            .uri("/swagger-ui/assets/style.css")
            .body(Empty::<Bytes>::new())
            .unwrap();

        let response = handle_swagger_request(&req, &config).await.unwrap();
        assert_eq!(response.status(), 404);
    }

    #[tokio::test]
    async fn test_handle_swagger_request_different_path() {
        let config = SwaggerUIConfig {
            enabled: true,
            path: "/custom-swagger".to_string(),
            sources: vec![],
        };

        let req = Request::builder()
            .method(Method::GET)
            .uri("/custom-swagger")
            .body(Empty::<Bytes>::new())
            .unwrap();

        let response = handle_swagger_request(&req, &config).await.unwrap();
        assert_eq!(response.status(), 200);
    }

    #[tokio::test]
    async fn test_handle_swagger_request_wrong_path() {
        let config = SwaggerUIConfig {
            enabled: true,
            path: "/swagger-ui".to_string(),
            sources: vec![],
        };

        let req = Request::builder()
            .method(Method::GET)
            .uri("/different-path")
            .body(Empty::<Bytes>::new())
            .unwrap();

        let response = handle_swagger_request(&req, &config).await.unwrap();
        assert_eq!(response.status(), 404);
    }

    #[tokio::test]
    async fn test_handle_swagger_request_post_method() {
        let config = SwaggerUIConfig {
            enabled: true,
            path: "/swagger-ui".to_string(),
            sources: vec![],
        };

        let req = Request::builder()
            .method(Method::POST)
            .uri("/swagger-ui")
            .body(Empty::<Bytes>::new())
            .unwrap();

        let response = handle_swagger_request(&req, &config).await.unwrap();
        assert_eq!(response.status(), 200); // Should still serve HTML regardless of method
    }

    #[tokio::test]
    async fn test_handle_swagger_request_html_content() {
        let config = SwaggerUIConfig {
            enabled: true,
            path: "/swagger-ui".to_string(),
            sources: vec![SwaggerSource {
                name: "Test API".to_string(),
                url: "/api/openapi.json".to_string(),
            }],
        };

        let req = Request::builder()
            .method(Method::GET)
            .uri("/swagger-ui")
            .body(Empty::<Bytes>::new())
            .unwrap();

        let response = handle_swagger_request(&req, &config).await.unwrap();
        assert_eq!(response.status(), 200);

        // We can't easily test the body content in this setup without additional dependencies
        // But we've verified the status and content-type headers
    }

    // Edge case tests
    #[test]
    fn test_swagger_source_empty_values() {
        let source = SwaggerSource {
            name: "".to_string(),
            url: "".to_string(),
        };

        assert_eq!(source.name, "");
        assert_eq!(source.url, "");

        // Test serialization/deserialization with empty values
        let json = serde_json::to_string(&source).expect("Failed to serialize");
        let deserialized: SwaggerSource =
            serde_json::from_str(&json).expect("Failed to deserialize");
        assert_eq!(deserialized.name, "");
        assert_eq!(deserialized.url, "");
    }

    #[test]
    fn test_swagger_source_unicode_values() {
        let source = SwaggerSource {
            name: "测试 API 🚀".to_string(),
            url: "/api/测试/openapi.json".to_string(),
        };

        let json = serde_json::to_string(&source).expect("Failed to serialize");
        let deserialized: SwaggerSource =
            serde_json::from_str(&json).expect("Failed to deserialize");
        assert_eq!(deserialized.name, "测试 API 🚀");
        assert_eq!(deserialized.url, "/api/测试/openapi.json");
    }

    #[test]
    fn test_swagger_ui_config_with_empty_path() {
        let config = SwaggerUIConfig {
            enabled: true,
            path: "".to_string(),
            sources: vec![],
        };

        assert!(config.enabled);
        assert_eq!(config.path, "");
    }

    #[test]
    fn test_swagger_ui_config_with_many_sources() {
        let mut sources = Vec::new();
        for i in 0..100 {
            sources.push(SwaggerSource {
                name: format!("API {}", i),
                url: format!("/api/v{}/openapi.json", i),
            });
        }

        let config = SwaggerUIConfig {
            enabled: true,
            path: "/swagger-ui".to_string(),
            sources,
        };

        assert_eq!(config.sources.len(), 100);
        assert_eq!(config.sources[0].name, "API 0");
        assert_eq!(config.sources[99].name, "API 99");
    }

    #[tokio::test]
    async fn test_handle_swagger_request_complex_path() {
        let config = SwaggerUIConfig {
            enabled: true,
            path: "/api/v1/docs/swagger-ui".to_string(),
            sources: vec![],
        };

        let req = Request::builder()
            .method(Method::GET)
            .uri("/api/v1/docs/swagger-ui")
            .body(Empty::<Bytes>::new())
            .unwrap();

        let response = handle_swagger_request(&req, &config).await.unwrap();
        assert_eq!(response.status(), 200);
    }

    #[tokio::test]
    async fn test_handle_swagger_request_path_with_query_params() {
        let config = SwaggerUIConfig {
            enabled: true,
            path: "/swagger-ui".to_string(),
            sources: vec![],
        };

        let req = Request::builder()
            .method(Method::GET)
            .uri("/swagger-ui?param=value")
            .body(Empty::<Bytes>::new())
            .unwrap();

        let response = handle_swagger_request(&req, &config).await.unwrap();
        assert_eq!(response.status(), 200);
    }

    #[tokio::test]
    async fn test_handle_swagger_request_case_sensitivity() {
        let config = SwaggerUIConfig {
            enabled: true,
            path: "/swagger-ui".to_string(),
            sources: vec![],
        };

        let req = Request::builder()
            .method(Method::GET)
            .uri("/Swagger-UI") // Different case
            .body(Empty::<Bytes>::new())
            .unwrap();

        let response = handle_swagger_request(&req, &config).await.unwrap();
        assert_eq!(response.status(), 404); // Should be case-sensitive
    }

    #[test]
    fn test_swagger_ui_config_deserialization_invalid_json() {
        let invalid_json = r#"{"enabled": "not_a_boolean"}"#;
        let result = serde_json::from_str::<SwaggerUIConfig>(invalid_json);
        assert!(result.is_err());
    }

    #[test]
    fn test_swagger_source_deserialization_missing_fields() {
        let incomplete_json = r#"{"name": "Test API"}"#; // Missing url field
        let result = serde_json::from_str::<SwaggerSource>(incomplete_json);
        assert!(result.is_err());
    }

    #[test]
    fn test_swagger_ui_config_deserialization_extra_fields() {
        let json_with_extra = r#"{
            "enabled": true,
            "path": "/swagger-ui",
            "sources": [],
            "extra_field": "should_be_ignored"
        }"#;
        let config: SwaggerUIConfig =
            serde_json::from_str(json_with_extra).expect("Should ignore extra fields");
        assert!(config.enabled);
        assert_eq!(config.path, "/swagger-ui");
    }
}
