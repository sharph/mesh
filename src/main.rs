#![allow(dead_code)]

use anyhow::Result;
use clap_conf::prelude::*;

mod crypto;
mod packetizer;
mod proto;
mod router;
mod tun;
mod udp;
mod unicast;
mod websockets;

#[tokio::main]
async fn main() -> Result<()> {
    let matches = clap_app!(mesh =>
        (author: "Sharp Hall <sharp@sharphall.org>")
        (version: crate_version!())
        (@arg config: -c --config +takes_value "Sets a custom config file")
        (@arg listen_addresses: -l --ws_listen +takes_value "A comma separated list of bind addresses")
        (@arg connect_addresses: -C --ws_connect +takes_value "A comma separated list of addresses to connect to")
        (@arg udp_listen_address: -u --udp_listen +takes_value "The UDP address to bind to")
        (@arg udp_connect_addresses: -U --udp_connect +takes_value "A comma separated list of addresses to connect to")
        (@arg tun: --tun +takes_value "Run tun interface")
    )
    .get_matches();
    let cfg = with_toml_env(&matches, ["config.toml"]);
    colog::init();
    let udp_listen = cfg
        .grab()
        .conf("udp.listen.address")
        .arg("udp_listen_address")
        .env("MESH_UDP_LISTEN_ADDRESS")
        .def("");
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async move {
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
                udp_listen: if !udp_listen.is_empty() {
                    Some(udp_listen)
                } else {
                    None
                },
                udp_connect: cfg
                    .grab()
                    .conf("udp.connect.addresses")
                    .arg("udp_connect_addresses")
                    .env("MESH_UDP_CONNECT_ADDRESSES")
                    .def("")
                    .split(",")
                    .filter(|s| s != &"")
                    .map(|s| s.to_string())
                    .collect(),
                tun: cfg.grab().arg("tun").def("false") == "true",
            })
            .await?;
            Ok(()) as Result<()>
        })
        .await?;
    Ok(())
}
