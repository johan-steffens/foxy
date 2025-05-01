// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Minimal CLI wrapper so the library can run as a stand-alone proxy.
//!
//!  Build it with `cargo build --release --bin foxy`
//!  The binary honours FOXY_CONFIG_FILE or falls back to /etc/foxy/config.toml.

use std::env;
use std::error::Error;
use foxy::Foxy;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // Prefer FOXY_CONFIG_FILE when present so the container user can
    // `docker run -v $(pwd)/config.toml:/etc/foxy/config.toml ...`
    let file_from_env = env::var("FOXY_CONFIG_FILE").ok();

    // Base loader always pulls env vars; file path is optional.
    let mut loader = Foxy::loader().with_env_vars();
    if let Some(ref path) = file_from_env {
        loader = loader.with_config_file(path);
    } else {
        // Conventional default inside the image
        loader = loader.with_config_file("/etc/foxy/config.toml");
    }

    // Build & run
    let proxy = loader.build().await?;
    proxy.start().await?;
    Ok(())
}