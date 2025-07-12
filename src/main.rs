use anyhow::Result;
use config::Config;

mod crypto;
mod node;
mod proto;
mod websockets;

#[tokio::main]
async fn main() -> Result<()> {
    println!("Hello, world!");
    let settings = Config::builder()
        .add_source(config::Environment::with_prefix("MESH"))
        .build()
        .unwrap();
    node::run_router(&settings).await?;
    Ok(())
}
