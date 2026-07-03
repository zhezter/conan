use bincode::config;
use conan_server::functions::handle_cmd;
use conanprotocol::{
    PeerConnection,
    comm::enums::{IPCCmd, IPCRes, encode},
    constants::DAEMON_SOCKET,
};
use std::{error::Error, fs};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::UnixListener,
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    _ = fs::remove_file(DAEMON_SOCKET);
    let listener = UnixListener::bind(DAEMON_SOCKET)?;
    let mut connection = PeerConnection::create().await?;
    loop {
        let (mut socket, _) = match listener.accept().await {
            Ok(s) => s,
            Err(_) => continue,
        };
        let mut buf = [0u8; 4096];
        loop {
            match socket.read(&mut buf).await {
                Ok(0) => {
                    break;
                }
                Ok(n) => {
                    println!("recieved: {:?}", &buf[..n]);
                    let cmd = match bincode::decode_from_slice::<IPCCmd, _>(
                        &buf[..n],
                        config::standard(),
                    ) {
                        Ok(s) => s.0,
                        Err(e) => {
                            let e = IPCRes::Error(e.to_string());
                            let res = encode(e);
                            socket.write_all(&res).await?;
                            continue;
                        }
                    };
                    let res = match handle_cmd(&mut connection, cmd).await {
                        Ok(s) => match s {
                            Some(s) => s,
                            None => IPCRes::Error("No Response Found".to_string()),
                        },
                        Err(e) => IPCRes::Error(format!("Server Error. {e}")),
                    };
                    let res = encode(res);
                    socket.write_all(&res).await?;
                }
                Err(e) => {
                    println!("error in main: {e}");
                }
            }
        }
    }
}
