use std::error::Error;
use foxy::Foxy;
use log::LevelFilter;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let foxy = Foxy::loader()
        .with_config_file("examples/basic-proxy/config.json")
        .build().await?;

    // Start the proxy server and wait for it to complete
    foxy.start().await?;
    Ok(())
}
