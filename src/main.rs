use anyhow::Result;
use config::Config;

mod crypto;
mod proto;
mod router;
mod websockets;

#[tokio::main]
async fn main() -> Result<()> {
    println!("Hello, world!");
    let settings = Config::builder()
        .add_source(config::Environment::with_prefix("MESH"))
        .build()
        .unwrap();
    router::run_router(&settings).await?;
    Ok(())
}
