use std::{error::Error, str::FromStr};

use conanprotocol::{
    PeerConnection,
    comm::enums::{IPCCmd, IPCRes},
    debug,
    msg::PeerStatus,
};
use tor_hsservice::HsId;

/// # Errors
pub async fn handle_cmd(
    connection: &mut PeerConnection,
    cmd: IPCCmd,
) -> Result<Option<IPCRes>, Box<dyn Error>> {
    let res = match cmd {
        IPCCmd::Tick => Some(IPCRes::Tock),
        IPCCmd::StartServer => {
            println!("Server initializing.");
            connection.init_server().await?;
            println!("Server Initialized");
            Some(IPCRes::ServerStarted)
        }
        IPCCmd::Connect(peer_addr, port) => {
            let hsid = match HsId::from_str(&peer_addr) {
                Ok(s) => s,
                Err(e) => return Ok(Some(IPCRes::Error(e.to_string()))),
            };
            debug!("Connecting to {peer_addr}...");
            let res: IPCRes = match connection.connect_as_dialer((hsid, port)).await {
                Ok(s) => match s {
                    PeerStatus::Connected => IPCRes::Connected(peer_addr, port),
                    PeerStatus::NotFound => IPCRes::Error("URL not found.".into()),
                },
                Err(e) => IPCRes::Error(e.to_string()),
            };
            Some(res)
        }
        _ => None,
    };
    Ok(res)
}
