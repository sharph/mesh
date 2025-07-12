use anyhow::Result;
use clap_conf::prelude::*;

mod crypto;
mod proto;
mod router;
mod websockets;

#[tokio::main]
async fn main() -> Result<()> {
    let matches = clap_app!(mesh =>
        (author: "Sharp Hall <sharp@sharphall.org>")
        (version: crate_version!())
        (@arg config: -c --config +takes_value "Sets a custom config file")
        (@arg listen_addresses: -l --ws_listen +takes_value "A comma separated list of bind addresses")
        (@arg connect_addresses: -C --ws_connect +takes_value "A comma separated list of addresses to connect to")
    )
    .get_matches();
    let cfg = with_toml_env(&matches, ["config.toml"]);
    router::run_router(&router::RouterConfig {
        websockets_connect: cfg
            .grab()
            .conf("connect.addresses")
            .arg("connect_addresses")
            .env("MESH_WS_CONNECT_ADDRESSES")
            .def("")
            .split(",")
            .filter(|s| s != &"")
            .map(|s| s.to_string())
            .collect(),
        websockets_listen: cfg
            .grab()
            .conf("listen.addresses")
            .arg("listen_addresses")
            .env("MESH_WS_LISTEN_ADDRESSES")
            .def("")
            .split(",")
            .filter(|s| s != &"")
            .map(|s| s.to_string())
            .collect(),
    })
    .await?;
    Ok(())
}
