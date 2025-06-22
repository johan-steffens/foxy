// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Proxy configuration module.

use serde::{Deserialize, Serialize};
use crate::logging::config::LoggingConfig;

/// Main proxy configuration
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ProxyConfig {
    /// Server configuration
    #[serde(default)]
    pub server: ServerConfig,

    /// Logging configuration
    #[serde(default)]
    pub logging: LoggingConfig,

    /// Client configuration
    #[serde(default)]
    pub client: ClientConfig,

    // Other proxy configuration fields can be added here
}

/// Server configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    /// Address to listen on
    #[serde(default = "default_listen")]
    pub listen: String,

    /// Maximum body size in bytes
    #[serde(default = "default_body_limit")]
    pub body_limit: usize,

    /// Maximum header size in bytes
    #[serde(default = "default_header_limit")]
    pub header_limit: usize,

    /// Enable HTTP/2 support on the server
    #[serde(default = "default_http2_enabled")]
    pub http2: bool,
}

fn default_listen() -> String {
    "[::]:8080".to_string()
}

fn default_body_limit() -> usize {
    5 * 1024 * 1024 // 5MB
}

fn default_header_limit() -> usize {
    256 * 1024 // 256KB
}

fn default_http2_enabled() -> bool {
    true // Enable HTTP/2 by default
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            listen: default_listen(),
            body_limit: default_body_limit(),
            header_limit: default_header_limit(),
            http2: default_http2_enabled(),
        }
    }
}

/// Client configuration for outbound requests
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientConfig {
    /// Enable HTTP/2 support for outbound requests
    #[serde(default = "default_client_http2_enabled")]
    pub http2: bool,

    /// Use HTTP/2 prior knowledge (skip protocol negotiation)
    #[serde(default = "default_http2_prior_knowledge")]
    pub http2_prior_knowledge: bool,

    /// Request timeout in seconds
    #[serde(default = "default_client_timeout")]
    pub timeout: u64,
}

fn default_client_http2_enabled() -> bool {
    true // Enable HTTP/2 by default for client
}

fn default_http2_prior_knowledge() -> bool {
    false // Use protocol negotiation by default
}

fn default_client_timeout() -> u64 {
    30 // 30 seconds default timeout
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            http2: default_client_http2_enabled(),
            http2_prior_knowledge: default_http2_prior_knowledge(),
            timeout: default_client_timeout(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json;

    #[test]
    fn test_server_config_default() {
        let config = ServerConfig::default();

        assert_eq!(config.listen, "[::]:8080");
        assert_eq!(config.body_limit, 5 * 1024 * 1024); // 5MB
        assert_eq!(config.header_limit, 256 * 1024); // 256KB
        assert_eq!(config.http2, true); // HTTP/2 enabled by default
    }

    #[test]
    fn test_server_config_custom() {
        let config = ServerConfig {
            listen: "127.0.0.1:9000".to_string(),
            body_limit: 10 * 1024 * 1024, // 10MB
            header_limit: 512 * 1024, // 512KB
            http2: false, // Disable HTTP/2
        };

        assert_eq!(config.listen, "127.0.0.1:9000");
        assert_eq!(config.body_limit, 10 * 1024 * 1024);
        assert_eq!(config.header_limit, 512 * 1024);
        assert_eq!(config.http2, false);
    }

    #[test]
    fn test_proxy_config_default() {
        let config = ProxyConfig::default();

        assert_eq!(config.server.listen, "[::]:8080");
        assert_eq!(config.server.body_limit, 5 * 1024 * 1024);
        assert_eq!(config.server.header_limit, 256 * 1024);
        assert_eq!(config.server.http2, true);

        assert_eq!(config.client.http2, true);
        assert_eq!(config.client.http2_prior_knowledge, false);
        assert_eq!(config.client.timeout, 30);
        // LoggingConfig default values are tested in the logging module
    }

    #[test]
    fn test_client_config_default() {
        let config = ClientConfig::default();

        assert_eq!(config.http2, true);
        assert_eq!(config.http2_prior_knowledge, false);
        assert_eq!(config.timeout, 30);
    }

    #[test]
    fn test_client_config_custom() {
        let config = ClientConfig {
            http2: false,
            http2_prior_knowledge: true,
            timeout: 60,
        };

        assert_eq!(config.http2, false);
        assert_eq!(config.http2_prior_knowledge, true);
        assert_eq!(config.timeout, 60);
    }

    #[test]
    fn test_server_config_serialization() {
        let config = ServerConfig::default();

        // Test serialization
        let serialized = serde_json::to_string(&config).expect("Failed to serialize ServerConfig");
        assert!(serialized.contains("\"listen\":\"[::]:8080\""));
        assert!(serialized.contains("\"body_limit\":5242880")); // 5MB in bytes
        assert!(serialized.contains("\"header_limit\":262144")); // 256KB in bytes

        // Test deserialization
        let deserialized: ServerConfig = serde_json::from_str(&serialized)
            .expect("Failed to deserialize ServerConfig");
        assert_eq!(deserialized.listen, config.listen);
        assert_eq!(deserialized.body_limit, config.body_limit);
        assert_eq!(deserialized.header_limit, config.header_limit);
    }

    #[test]
    fn test_proxy_config_serialization() {
        let config = ProxyConfig::default();

        // Test serialization
        let serialized = serde_json::to_string(&config).expect("Failed to serialize ProxyConfig");
        assert!(serialized.contains("\"server\""));
        assert!(serialized.contains("\"logging\""));

        // Test deserialization
        let deserialized: ProxyConfig = serde_json::from_str(&serialized)
            .expect("Failed to deserialize ProxyConfig");
        assert_eq!(deserialized.server.listen, config.server.listen);
        assert_eq!(deserialized.server.body_limit, config.server.body_limit);
        assert_eq!(deserialized.server.header_limit, config.server.header_limit);
    }

    #[test]
    fn test_server_config_partial_deserialization() {
        // Test that partial JSON can be deserialized with defaults
        let partial_json = r#"{"listen": "0.0.0.0:3000"}"#;
        let config: ServerConfig = serde_json::from_str(partial_json)
            .expect("Failed to deserialize partial ServerConfig");

        assert_eq!(config.listen, "0.0.0.0:3000");
        assert_eq!(config.body_limit, 5 * 1024 * 1024); // default
        assert_eq!(config.header_limit, 256 * 1024); // default
    }

    #[test]
    fn test_server_config_full_deserialization() {
        let full_json = r#"{
            "listen": "192.168.1.100:8888",
            "body_limit": 1048576,
            "header_limit": 131072
        }"#;
        let config: ServerConfig = serde_json::from_str(full_json)
            .expect("Failed to deserialize full ServerConfig");

        assert_eq!(config.listen, "192.168.1.100:8888");
        assert_eq!(config.body_limit, 1048576); // 1MB
        assert_eq!(config.header_limit, 131072); // 128KB
    }

    #[test]
    fn test_proxy_config_partial_deserialization() {
        let partial_json = r#"{
            "server": {
                "listen": "localhost:4000"
            }
        }"#;
        let config: ProxyConfig = serde_json::from_str(partial_json)
            .expect("Failed to deserialize partial ProxyConfig");

        assert_eq!(config.server.listen, "localhost:4000");
        assert_eq!(config.server.body_limit, 5 * 1024 * 1024); // default
        assert_eq!(config.server.header_limit, 256 * 1024); // default
    }

    #[test]
    fn test_default_functions() {
        assert_eq!(default_listen(), "[::]:8080");
        assert_eq!(default_body_limit(), 5 * 1024 * 1024);
        assert_eq!(default_header_limit(), 256 * 1024);
    }

    #[test]
    fn test_server_config_debug() {
        let config = ServerConfig::default();
        let debug_str = format!("{:?}", config);

        assert!(debug_str.contains("ServerConfig"));
        assert!(debug_str.contains("[::]:8080"));
        assert!(debug_str.contains("5242880")); // 5MB
        assert!(debug_str.contains("262144")); // 256KB
    }

    #[test]
    fn test_proxy_config_debug() {
        let config = ProxyConfig::default();
        let debug_str = format!("{:?}", config);

        assert!(debug_str.contains("ProxyConfig"));
        assert!(debug_str.contains("server"));
        assert!(debug_str.contains("logging"));
    }

    #[test]
    fn test_server_config_clone() {
        let config = ServerConfig::default();
        let cloned = config.clone();

        assert_eq!(config.listen, cloned.listen);
        assert_eq!(config.body_limit, cloned.body_limit);
        assert_eq!(config.header_limit, cloned.header_limit);
    }

    #[test]
    fn test_proxy_config_clone() {
        let config = ProxyConfig::default();
        let cloned = config.clone();

        assert_eq!(config.server.listen, cloned.server.listen);
        assert_eq!(config.server.body_limit, cloned.server.body_limit);
        assert_eq!(config.server.header_limit, cloned.server.header_limit);
    }

    #[test]
    fn test_server_config_edge_cases() {
        // Test with zero values
        let config = ServerConfig {
            listen: "".to_string(),
            body_limit: 0,
            header_limit: 0,
            http2: false,
        };

        assert_eq!(config.listen, "");
        assert_eq!(config.body_limit, 0);
        assert_eq!(config.header_limit, 0);

        // Test serialization/deserialization of edge cases
        let serialized = serde_json::to_string(&config).expect("Failed to serialize edge case config");
        let deserialized: ServerConfig = serde_json::from_str(&serialized)
            .expect("Failed to deserialize edge case config");

        assert_eq!(deserialized.listen, config.listen);
        assert_eq!(deserialized.body_limit, config.body_limit);
        assert_eq!(deserialized.header_limit, config.header_limit);
    }

    #[test]
    fn test_server_config_large_values() {
        // Test with large values
        let config = ServerConfig {
            listen: "0.0.0.0:65535".to_string(),
            body_limit: usize::MAX,
            header_limit: usize::MAX,
            http2: true,
        };

        assert_eq!(config.listen, "0.0.0.0:65535");
        assert_eq!(config.body_limit, usize::MAX);
        assert_eq!(config.header_limit, usize::MAX);
    }

    #[test]
    fn test_invalid_json_deserialization() {
        let invalid_json = r#"{"listen": "localhost:8080", "body_limit": "not_a_number"}"#;
        let result = serde_json::from_str::<ServerConfig>(invalid_json);
        assert!(result.is_err());
    }

    #[test]
    fn test_empty_json_deserialization() {
        let empty_json = "{}";
        let config: ServerConfig = serde_json::from_str(empty_json)
            .expect("Failed to deserialize empty JSON");

        // Should use all defaults
        assert_eq!(config.listen, "[::]:8080");
        assert_eq!(config.body_limit, 5 * 1024 * 1024);
        assert_eq!(config.header_limit, 256 * 1024);
        assert_eq!(config.http2, true);
    }
}
