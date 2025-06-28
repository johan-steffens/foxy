// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Serves an embedded Swagger UI.
//!
//! This module is only available when the `swagger-ui` feature is enabled.
//! It serves a single HTML page that loads the Swagger UI assets from a CDN
//! and is configured dynamically based on the `swagger_ui` section in the
//! configuration file.

use bytes::Bytes;
use std::convert::Infallible;

use hyper::body::Incoming;
use hyper::{Request, Response, StatusCode, header};
use reqwest::Body;
use serde::{Deserialize, Serialize};

/// Configuration for a single Swagger source (API specification).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SwaggerSource {
    /// The name of the API, which will be displayed in the Swagger UI dropdown.
    pub name: String,
    /// The URL to the OpenAPI specification file (e.g., `/api/v1/openapi.json`).
    pub url: String,
}

/// Configuration for the Swagger UI feature.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SwaggerUIConfig {
    /// Whether the Swagger UI is enabled.
    #[serde(default)]
    pub enabled: bool,
    /// The base path under which the Swagger UI will be served (e.g., `/swagger-ui`).
    #[serde(default = "default_swagger_path")]
    pub path: String,
    /// A list of API sources to be displayed in the Swagger UI.
    #[serde(default)]
    pub sources: Vec<SwaggerSource>,
}

fn default_swagger_path() -> String {
    "/swagger-ui".to_string()
}

impl Default for SwaggerUIConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            path: default_swagger_path(),
            sources: Vec::new(),
        }
    }
}

/// Generates the `urls` configuration array for Swagger UI.
fn generate_urls_config(sources: &[SwaggerSource]) -> String {
    if sources.is_empty() {
        return "[]".to_string();
    }
    let mut urls_json = String::from("[");
    for (i, source) in sources.iter().enumerate() {
        urls_json.push_str(&format!(
            "{{ url: \"{}\", name: \"{}\" }}",
            source.url, source.name
        ));
        if i < sources.len() - 1 {
            urls_json.push_str(", ");
        }
    }
    urls_json.push(']');
    urls_json
}

/// Generates the full HTML page for the Swagger UI.
fn generate_html(config: &SwaggerUIConfig) -> String {
    let urls_config = generate_urls_config(&config.sources);

    // Set the `url` parameter to the first source to ensure a default is loaded.
    let default_url = config.sources.first().map_or("", |s| &s.url);

    format!(
        r#"
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Foxy Swagger UI</title>
  <link rel="stylesheet" type="text/css" href="https://unpkg.com/swagger-ui-dist@5.24.0/swagger-ui.css">
  <style>
    html {{ box-sizing: border-box; overflow: -moz-scrollbars-vertical; overflow-y: scroll; }}
    *, *:before, *:after {{ box-sizing: inherit; }}
    body {{ margin:0; background: #fafafa; }}
  </style>
</head>
<body>
  <div id="swagger-ui"></div>
  <script src="https://unpkg.com/swagger-ui-dist@5.24.0/swagger-ui-bundle.js" charset="UTF-8" crossorigin></script>
  <script src="https://unpkg.com/swagger-ui-dist@5.24.0/swagger-ui-standalone-preset.js" crossorigin></script>
  <script>
      window.onload = () => {{
        window.ui = SwaggerUIBundle({{
            url: '{default_url}',
            urls: {urls_config},
            dom_id: '#swagger-ui',
            deepLinking: true,
            presets: [
              SwaggerUIBundle.presets.apis,
              SwaggerUIStandalonePreset
            ],
            layout: "StandaloneLayout",
        }});
      }};
  </script>
</body>
</html>
"#,
        default_url = default_url,
        urls_config = urls_config
    )
}

/// Handles incoming requests for the Swagger UI.
pub async fn handle_swagger_request(
    req: &Request<Incoming>,
    config: &SwaggerUIConfig,
) -> Result<Response<Body>, Infallible> {
    let path = req.uri().path();
    let root_path = &config.path;
    let index_path = format!("{}/index.html", root_path);

    // Serve the main HTML file for the root index path (with trailing slash) or index.html
    if path == *root_path || path == format!("{root_path}/") || path == index_path {
        let html = generate_html(config);
        return Ok(Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, "text/html; charset=utf-8")
            .body(Body::from(Bytes::from(html)))
            .unwrap());
    }

    // For any other path under the swagger root, return 404
    Ok(Response::builder()
        .status(StatusCode::NOT_FOUND)
        .body(Body::from(Bytes::from("Not Found")))
        .unwrap())
}
